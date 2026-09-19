report-ver : ok header : ok //
//  NDSpoofer.m  —  百度网盘（com.baidu.netdisk）设备指纹伪装 dylib（卐解）
//
//  版本：9.20-01
//
//  设计原则（与探针 NDProbe2/NDProbe3 证据一一对应）：
//   1. 只在 com.baidu.netdisk 主进程生效，扩展（.appex/PlugIns）不生效。
//   2. 只走原生层：sysctl/uname/statfs C 层 interpose + Objective-C runtime swizzle，
//      绝不注入 JS、不改网页 DOM/JS 环境、不动 Mobile/15E148。
//   2a. 9.20-01 新增原生 UA 出口改写（非 JS）：WKWebView setCustomUserAgent:、
//      BDPUserAgent webViewDefaultUserAgent、NSMutableURLRequest UA 头、
//      NSURLSession dataTask 出口；覆盖 WAP 登录页与 native 登录链。
//   3. 机型池只允许与真机同屏（375x667 @2x / 750x1334）的机型，UIScreen 不 hook，
//      从根上消除“机型与屏幕矛盾”。
//   4. 不碰 App 版本、Sapi SDK 版本、tpl、cuid/utdid/deviceID、TeamID、运营商（默认）。
//   5. 任何开关关闭或配置缺失一律透传原实现；hook 安装前做类型编码校验，不匹配就不装。
//
//  配置文件：容器 Documents/ndspoofer_config.plist（由“网盘解”管理器逐容器写入）。
//

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <dlfcn.h>
#import <mach-o/dyld.h>
#import <sys/utsname.h>
#import <sys/sysctl.h>
#import <sys/param.h>
#import <sys/mount.h>
#import <os/lock.h>
#import <stdatomic.h>

#if __has_include(<mach-o/dyld-interposing.h>)
#import <mach-o/dyld-interposing.h>
#else
#define DYLD_INTERPOSE(_replacement, _replacee) \
    __attribute__((used)) static struct { const void *replacement; const void *replacee; } \
    _nd_interpose_##_replacee __attribute__((section("__DATA,__interpose"))) = { \
        (const void *)(uintptr_t)&_replacement, (const void *)(uintptr_t)&_replacee \
    };
#endif

static NSString * const NDBundleID      = @"com.baidu.netdisk";
static NSString * const NDConfigFileName = @"ndspoofer_config.plist";

// ============================== 配置快照 ==============================

@interface NDConfig : NSObject
@property(nonatomic, assign) BOOL enabled;
@property(nonatomic, assign) BOOL spoofSysctl;
@property(nonatomic, assign) BOOL spoofUIDevice;
@property(nonatomic, assign) BOOL spoofBaiduSDK;
@property(nonatomic, assign) BOOL spoofUA;
@property(nonatomic, assign) BOOL spoofIDFV;
@property(nonatomic, assign) BOOL spoofStorage;
@property(nonatomic, assign) BOOL seedPassCustom;
@property(nonatomic, copy) NSString *hwMachine;
@property(nonatomic, copy) NSString *hwModel;
@property(nonatomic, copy) NSString *systemVersion;
@property(nonatomic, copy) NSString *systemBuild;
@property(nonatomic, copy) NSString *marketingName;
@property(nonatomic, copy) NSString *cpuBrand;
@property(nonatomic, copy) NSString *kernHostname;
@property(nonatomic, assign) NSInteger memorySizeMB;
@property(nonatomic, assign) NSInteger diskSizeGB;
@property(nonatomic, copy) NSString *idfv;
@property(nonatomic, copy) NSString *passSdkVersion;
// 真机基线（只读，用于字符串比对替换）
@property(nonatomic, copy) NSString *realMachine;
@property(nonatomic, copy) NSString *realModel;
@property(nonatomic, copy) NSString *realOSVersion;
@property(nonatomic, copy) NSString *realBuild;
@property(nonatomic, assign) uint64_t realMemBytes;
@property(nonatomic, assign) uint64_t realDiskBytes;
@end
@implementation NDConfig
@end

static NDConfig *g_cfg = nil;
static os_unfair_lock g_cfgLock = OS_UNFAIR_LOCK_INIT;

static NSString *NDConfigPath(void) {
    NSString *docs = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    return [docs stringByAppendingPathComponent:NDConfigFileName];
}

static NSString *NDCfgStr(NSDictionary *d, NSString *key, NSString *def) {
    id v = d[key];
    return ([v isKindOfClass:NSString.class] && [v length]) ? v : def;
}
static BOOL NDCfgBool(NSDictionary *d, NSString *key, BOOL def) {
    id v = d[key];
    return [v isKindOfClass:NSNumber.class] ? [v boolValue] : def;
}
static NSInteger NDCfgInt(NSDictionary *d, NSString *key, NSInteger def) {
    id v = d[key];
    return [v isKindOfClass:NSNumber.class] ? [v integerValue] : def;
}

static NSString *NDRealSysctlStr(const char *name) {
    size_t len = 0;
    if (sysctlbyname(name, NULL, &len, NULL, 0) != 0 || len == 0) return nil;
    char buf[256] = {0};
    if (len >= sizeof(buf)) len = sizeof(buf) - 1;
    if (sysctlbyname(name, buf, &len, NULL, 0) != 0) return nil;
    return [NSString stringWithUTF8String:buf];
}
static uint64_t NDRealSysctlU64(const char *name) {
    uint64_t v = 0; size_t len = sizeof(v);
    if (sysctlbyname(name, &v, &len, NULL, 0) != 0) return 0;
    return v;
}
static uint64_t NDRealDiskBytes(void) {
    struct statfs s;
    memset(&s, 0, sizeof(s));
    if (statfs("/private/var", &s) != 0) {
        if (statfs("/", &s) != 0) return 0;
    }
    return (uint64_t)s.f_bsize * (uint64_t)s.f_blocks;
}

static NDConfig *NDCurrentConfig(void) {
    os_unfair_lock_lock(&g_cfgLock);
    NDConfig *c = g_cfg;
    os_unfair_lock_unlock(&g_cfgLock);
    return c;
}

static void NDLoadConfig(void) {
    @autoreleasepool {
        NSString *path = NDConfigPath();
        NSDictionary *d = [NSDictionary dictionaryWithContentsOfFile:path] ?: @{};

        NDConfig *c = [[NDConfig alloc] init];
        c.enabled          = NDCfgBool(d, @"enabled", NO);
        c.spoofSysctl      = NDCfgBool(d, @"spoofSysctl", NO);
        c.spoofUIDevice    = NDCfgBool(d, @"spoofUIDevice", NO);
        c.spoofBaiduSDK    = NDCfgBool(d, @"spoofBaiduSDK", NO);
        c.spoofUA          = NDCfgBool(d, @"spoofUA", NO);
        c.spoofIDFV        = NDCfgBool(d, @"spoofIDFV", NO);
        c.spoofStorage     = NDCfgBool(d, @"spoofStorage", NO);
        c.seedPassCustom   = NDCfgBool(d, @"seedPassCustom", NO);
        c.hwMachine        = NDCfgStr(d, @"hwMachine", @"");
        c.hwModel          = NDCfgStr(d, @"hwModel", @"");
        c.systemVersion    = NDCfgStr(d, @"systemVersion", @"");
        c.systemBuild      = NDCfgStr(d, @"systemBuild", @"");
        c.marketingName    = NDCfgStr(d, @"marketingName", @"");
        c.cpuBrand         = NDCfgStr(d, @"cpuBrand", @"");
        c.kernHostname     = NDCfgStr(d, @"kernHostname", @"");
        c.memorySizeMB     = NDCfgInt(d, @"memorySize", 0);
        c.diskSizeGB       = NDCfgInt(d, @"diskSize", 0);
        c.idfv             = NDCfgStr(d, @"idfv", @"");
        c.passSdkVersion   = NDCfgStr(d, @"passSdkVersion", @"9.8.12.20");

        c.realMachine   = NDRealSysctlStr("hw.machine") ?: @"";
        c.realModel     = NDRealSysctlStr("hw.model") ?: @"";
        c.realOSVersion = UIDevice.currentDevice.systemVersion ?: @"";
        c.realBuild     = NDRealSysctlStr("kern.osversion") ?: @"";
        c.realMemBytes  = NDRealSysctlU64("hw.memsize");
        c.realDiskBytes = NDRealDiskBytes();

        os_unfair_lock_lock(&g_cfgLock);
        g_cfg = c;
        os_unfair_lock_unlock(&g_cfgLock);
    }
}

// ============================== C 层 interpose ==============================
// 直接调用原符号：dyld 对 interpose 镜像自身的绑定保留为原实现，不会递归。
// 禁止 dlsym(RTLD_NEXT)：其结果仍会应用 interpose，可能解析回本包装函数造成无限递归。

static void NDWriteCString(void *oldp, size_t *oldlenp, NSString *value) {
    if (!oldp || !oldlenp || !value.length) return;
    const char *s = value.UTF8String;
    size_t need = strlen(s) + 1;
    if (*oldlenp < need) return;                 // 缓冲不足，保留原值，绝不越界
    memset(oldp, 0, *oldlenp);
    memcpy(oldp, s, need);
    *oldlenp = need;
}
static void NDWriteU64(void *oldp, size_t *oldlenp, uint64_t value) {
    if (!oldp || !oldlenp || *oldlenp < sizeof(uint64_t)) return;
    memset(oldp, 0, *oldlenp);
    memcpy(oldp, &value, sizeof(uint64_t));
    *oldlenp = sizeof(uint64_t);
}

static int nd_sysctlbyname(const char *name, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    int r = sysctlbyname(name, oldp, oldlenp, newp, newlen);
    NDConfig *c = NDCurrentConfig();
    if (r != 0 || !c.enabled || !c.spoofSysctl || !name || !oldp || !oldlenp) return r;

    if (strcmp(name, "hw.machine") == 0) {
        NDWriteCString(oldp, oldlenp, c.hwMachine);
    } else if (strcmp(name, "hw.model") == 0) {
        NDWriteCString(oldp, oldlenp, c.hwModel);
    } else if (strcmp(name, "kern.osversion") == 0) {
        NDWriteCString(oldp, oldlenp, c.systemBuild);
    } else if (strcmp(name, "kern.osproductversion") == 0) {
        NDWriteCString(oldp, oldlenp, c.systemVersion);
    } else if (strcmp(name, "kern.hostname") == 0) {
        NDWriteCString(oldp, oldlenp, c.kernHostname);
    } else if (strcmp(name, "machdep.cpu.brand_string") == 0 && c.cpuBrand.length) {
        NDWriteCString(oldp, oldlenp, c.cpuBrand);
    } else if (strcmp(name, "hw.memsize") == 0 || strcmp(name, "hw.physmem") == 0) {
        if (c.memorySizeMB > 0) NDWriteU64(oldp, oldlenp, (uint64_t)c.memorySizeMB * 1024ULL * 1024ULL);
    }
    return r;
}

static int nd_sysctl(int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    int r = sysctl(name, namelen, oldp, oldlenp, newp, newlen);
    NDConfig *c = NDCurrentConfig();
    if (r != 0 || !c.enabled || !c.spoofSysctl || !name || namelen < 2 || !oldp || !oldlenp) return r;

    if (name[0] == CTL_HW) {
        switch (name[1]) {
            case HW_MACHINE: NDWriteCString(oldp, oldlenp, c.hwMachine); break;
            case HW_MODEL:   NDWriteCString(oldp, oldlenp, c.hwModel); break;
            case HW_MEMSIZE:
            case HW_PHYSMEM:
                if (c.memorySizeMB > 0) NDWriteU64(oldp, oldlenp, (uint64_t)c.memorySizeMB * 1024ULL * 1024ULL);
                break;
            default: break;
        }
    } else if (name[0] == CTL_KERN) {
        if (name[1] == KERN_OSVERSION) {
            NDWriteCString(oldp, oldlenp, c.systemBuild);
        } else if (name[1] == KERN_HOSTNAME) {
            NDWriteCString(oldp, oldlenp, c.kernHostname);
        }
#ifdef KERN_OSPRODUCT_VERSION
        else if (name[1] == KERN_OSPRODUCT_VERSION) {
            NDWriteCString(oldp, oldlenp, c.systemVersion);
        }
#endif
    }
    return r;
}

static int nd_uname(struct utsname *name) {
    int r = uname(name);
    NDConfig *c = NDCurrentConfig();
    if (r != 0 || !c.enabled || !c.spoofSysctl || !name || !c.hwMachine.length) return r;
    strncpy(name->machine, c.hwMachine.UTF8String, sizeof(name->machine) - 1);
    name->machine[sizeof(name->machine) - 1] = '\0';
    return r;
}

static int nd_statfs(const char *path, struct statfs *buf) {
    int r = statfs(path, buf);
    NDConfig *c = NDCurrentConfig();
    if (r != 0 || !c.enabled || !c.spoofStorage || !buf || !path || c.diskSizeGB <= 0) return r;
    // 只动数据卷；总量不变（64GB 真机 + 64GB 档案）时根本不进分支。
    if (strcmp(path, "/") != 0 && strncmp(path, "/private/var", 12) != 0) return r;
    uint64_t bsize = (uint64_t)buf->f_bsize;
    uint64_t total = bsize * (uint64_t)buf->f_blocks;
    if (total < (10ULL * 1024 * 1024 * 1024)) return r;
    uint64_t fakeTotal = (uint64_t)c.diskSizeGB * 1024ULL * 1024ULL * 1024ULL;
    if (fakeTotal == total) return r;
    uint64_t availBytes = bsize * (uint64_t)buf->f_bavail;
    uint64_t newBlocks = fakeTotal / bsize;
    uint64_t newAvail  = availBytes / bsize;
    if (newBlocks <= newAvail) return r;              // 装不下真实空闲量就不动，保证不出现负数
    buf->f_blocks = (fsblkcnt_t)newBlocks;
    buf->f_bfree  = (fsblkcnt_t)newAvail;
    buf->f_bavail = (fsblkcnt_t)newAvail;
    return r;
}

DYLD_INTERPOSE(nd_sysctlbyname, sysctlbyname)
DYLD_INTERPOSE(nd_sysctl,      sysctl)
DYLD_INTERPOSE(nd_uname,       uname)
DYLD_INTERPOSE(nd_statfs,      statfs)

// ============================== UA / 明文字符串改写 ==============================

static NSString *NDEscapedTemplate(NSString *s) {
    return [NSRegularExpression escapedTemplateForString:s];
}

static NSString *NDMachineEncoded(NSString *machine) {
    return [machine stringByReplacingOccurrencesOfString:@"," withString:@"%2C"];
}

// 通用 UA 改写：只改机型与系统版本，Mobile/15E148 永不触碰。
static NSString *NDRewriteUA(NSString *s, NDConfig *c) {
    if (![s isKindOfClass:NSString.class] || !s.length) return s;
    NSString *out = s;
    NSString *fakeUnder = [c.systemVersion stringByReplacingOccurrencesOfString:@"." withString:@"_"];
    NSString *realUnder = [c.realOSVersion stringByReplacingOccurrencesOfString:@"." withString:@"_"];

    // CPU iPhone OS 16_3 like
    NSError *err = nil;
    NSRegularExpression *rxCPU = [NSRegularExpression regularExpressionWithPattern:
        @"CPU iPhone OS \\d+_\\d+(?:_\\d+)? like" options:0 error:&err];
    out = [rxCPU stringByReplacingMatchesInString:out options:0 range:NSMakeRange(0, out.length)
                                    withTemplate:NDEscapedTemplate([NSString stringWithFormat:@"CPU iPhone OS %@ like", fakeUnder])];

    // (iPhone12,8; iOS 16.3)
    NSRegularExpression *rxMachineUA = [NSRegularExpression regularExpressionWithPattern:
        @"\\(iPhone\\d+,\\d+;\\s*iOS \\d+(?:\\.\\d+)*\\)" options:0 error:&err];
    out = [rxMachineUA stringByReplacingMatchesInString:out options:0 range:NSMakeRange(0, out.length)
                                          withTemplate:NDEscapedTemplate([NSString stringWithFormat:@"(%@; iOS %@)", c.hwMachine, c.systemVersion])];

    // (iPhone; iOS 16.3)
    NSRegularExpression *rxPhoneUA = [NSRegularExpression regularExpressionWithPattern:
        @"\\(iPhone;\\s*iOS \\d+(?:\\.\\d+)*\\)" options:0 error:&err];
    out = [rxPhoneUA stringByReplacingMatchesInString:out options:0 range:NSMakeRange(0, out.length)
                                         withTemplate:NDEscapedTemplate([NSString stringWithFormat:@"(iPhone; iOS %@)", c.systemVersion])];

    // (Baidu; P2 16.3)
    NSRegularExpression *rxBaidu = [NSRegularExpression regularExpressionWithPattern:
        @"\\(Baidu;\\s*P2 \\d+(?:\\.\\d+)*\\)" options:0 error:&err];
    out = [rxBaidu stringByReplacingMatchesInString:out options:0 range:NSMakeRange(0, out.length)
                                       withTemplate:NDEscapedTemplate([NSString stringWithFormat:@"(Baidu; P2 %@)", c.systemVersion])];

    // 百分号编码机型：iPhone12%2C8
    NSString *realEnc = NDMachineEncoded(c.realMachine);
    NSString *fakeEnc = NDMachineEncoded(c.hwMachine);
    if (realEnc.length && ![realEnc isEqualToString:fakeEnc]) {
        out = [out stringByReplacingOccurrencesOfString:realEnc withString:fakeEnc];
    }
    // 裸机型：iPhone12,8
    if (c.realMachine.length && ![c.realMachine isEqualToString:c.hwMachine]) {
        out = [out stringByReplacingOccurrencesOfString:c.realMachine withString:c.hwMachine];
    }
    // 分号 UA 中的营销名：netdisk;13.33.5;iPhoneSE2;ios-iphone;16.3;zh_CN
    if (c.marketingName.length) {
        // 真实营销名候选：iPhoneSE2 以及真机 machine 派生名，逐字面值替换，避免级联。
        for (NSString *realMarketing in @[@"iPhoneSE2", @"iPhoneSE3", @"Unknown_iPhone"]) {
            if (![realMarketing isEqualToString:c.marketingName]) {
                out = [out stringByReplacingOccurrencesOfString:
                    [NSString stringWithFormat:@";%@;", realMarketing]
                    withString:[NSString stringWithFormat:@";%@;", c.marketingName]];
            }
        }
    }
    // 分号 UA 中的系统版本段：;16.3;
    if (c.realOSVersion.length && ![c.realOSVersion isEqualToString:c.systemVersion]) {
        out = [out stringByReplacingOccurrencesOfString:
            [NSString stringWithFormat:@";%@;", c.realOSVersion]
            withString:[NSString stringWithFormat:@";%@;", c.systemVersion]];
        // Sapi UA 中的 _16.3_ / _16_3
        out = [out stringByReplacingOccurrencesOfString:
            [NSString stringWithFormat:@"_%@_", c.realOSVersion]
            withString:[NSString stringWithFormat:@"_%@_", c.systemVersion]];
        if (realUnder.length) {
            out = [out stringByReplacingOccurrencesOfString:
                [NSString stringWithFormat:@"_%@_", realUnder]
                withString:[NSString stringWithFormat:@"_%@_", fakeUnder]];
        }
    }
    return out;
}

// useagent_getDeviceInfo 字符串形态：iPhone12,8_16.3
static NSString *NDRewriteDeviceInfoLine(NSString *s, NDConfig *c) {
    if (![s isKindOfClass:NSString.class] || !s.length) return s;
    if ([s rangeOfString:@"_"].location == NSNotFound) return NDRewriteUA(s, c);
    NSRange under = [s rangeOfString:@"_" options:NSBackwardsSearch];
    NSString *head = [s substringToIndex:under.location];
    NSString *tail = [s substringFromIndex:under.location]; // 含下划线
    NSRegularExpression *verTail = [NSRegularExpression regularExpressionWithPattern:
        @"^_\\d+(?:\\.\\d+)*$" options:0 error:nil];
    if (![verTail firstMatchInString:tail options:0 range:NSMakeRange(0, tail.length)]) {
        return NDRewriteUA(s, c);
    }
    if ([head containsString:c.realMachine]) {
        head = [head stringByReplacingOccurrencesOfString:c.realMachine withString:c.hwMachine];
    }
    return [NSString stringWithFormat:@"%@_%@", head, c.systemVersion];
}

// SAPI 明文串（空格分隔）按 token 精确替换：机型、系统版本、总内存(KB)、总磁盘(KB)
static NSString *NDRewriteSapiPlain(NSString *s, NDConfig *c) {
    if (![s isKindOfClass:NSString.class] || !s.length) return s;
    if ([s rangeOfString:@" "].location == NSNotFound) return s;
    NSMutableArray<NSString *> *tokens = [[s componentsSeparatedByString:@" "] mutableCopy];

    NSString *realMemKB = c.realMemBytes ? [NSString stringWithFormat:@"%llu", c.realMemBytes / 1024ULL] : nil;
    NSString *fakeMemKB = c.memorySizeMB > 0 ? [NSString stringWithFormat:@"%ld", (long)c.memorySizeMB * 1024L] : nil;
    NSString *realDiskKB = c.realDiskBytes ? [NSString stringWithFormat:@"%llu", c.realDiskBytes / 1024ULL] : nil;
    NSString *fakeDiskKB = c.diskSizeGB > 0 ? [NSString stringWithFormat:@"%lld", (long long)c.diskSizeGB * 1024LL * 1024LL] : nil;

    NSRegularExpression *verRx = [NSRegularExpression regularExpressionWithPattern:
        @"^\\d+\\.\\d+(?:\\.\\d+)?$" options:0 error:nil];
    for (NSUInteger i = 0; i < tokens.count; i++) {
        NSString *tok = tokens[i];
        if (c.realMachine.length && [tok isEqualToString:c.realMachine]) {
            tokens[i] = c.hwMachine;
            if (i + 1 < tokens.count &&
                [verRx firstMatchInString:tokens[i+1] options:0 range:NSMakeRange(0, tokens[i+1].length)] &&
                [tokens[i+1] isEqualToString:c.realOSVersion]) {
                tokens[i+1] = c.systemVersion;
            }
            continue;
        }
        if (realMemKB && fakeMemKB && [tok isEqualToString:realMemKB]) { tokens[i] = fakeMemKB; continue; }
        if (realDiskKB && fakeDiskKB && [tok isEqualToString:realDiskKB]) { tokens[i] = fakeDiskKB; continue; }
    }
    return [tokens componentsJoinedByString:@" "];
}

// 字典白名单键：只改机型/系统版本承载键
static NSSet<NSString *> *NDSapiDictKeys(void) {
    static NSSet *keys;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        keys = [NSSet setWithArray:@[@"PhoneModel", @"phoneModel", @"SystemVersion",
                                     @"osVersion", @"systemVersion", @"model", @"machine", @"hwMachine"]];
    });
    return keys;
}

static NSDictionary *NDRewriteDict(NSDictionary *d, NDConfig *c, BOOL sapi) {
    if (![d isKindOfClass:NSDictionary.class]) return d;
    NSMutableDictionary *m = d.mutableCopy;
    [m enumerateKeysAndObjectsUsingBlock:^(id key, id obj, BOOL *stop) {
        if (![key isKindOfClass:NSString.class]) return;
        NSString *k = key;
        if (![NDSapiDictKeys() containsObject:k]) return;
        if ([obj isKindOfClass:NSString.class]) {
            NSString *v = obj;
            if ([v isEqualToString:c.realMachine]) { m[k] = c.hwMachine; return; }
            if ([v isEqualToString:c.realOSVersion]) { m[k] = c.systemVersion; return; }
            if (sapi && ([k isEqualToString:@"PhoneModel"] || [k isEqualToString:@"phoneModel"])) {
                m[k] = c.hwMachine;
            } else if ([k isEqualToString:@"SystemVersion"] || [k isEqualToString:@"osVersion"] ||
                       [k isEqualToString:@"systemVersion"]) {
                m[k] = c.systemVersion;
            }
        }
    }];
    return m;
}

// ============================== Objective-C hooks ==============================

static IMP nd_o_systemVersion = NULL;
static IMP nd_o_model = NULL;
static IMP nd_o_localizedModel = NULL;
static IMP nd_o_name = NULL;
static IMP nd_o_platform = NULL;
static IMP nd_o_bdcPlatform = NULL;
static IMP nd_o_bbaSysVer = NULL;
static IMP nd_o_idfv = NULL;
static IMP nd_o_sapiDeviceModel = NULL;
static IMP nd_o_sapiDeviceName = NULL;
static IMP nd_o_sapiDeviceType = NULL;
static IMP nd_o_sapiPlain = NULL;
static IMP nd_o_sapiRetrieve = NULL;
static IMP nd_o_sapiGenerate = NULL;
static IMP nd_o_uaGet = NULL;
static IMP nd_o_uaCompose = NULL;

static int g_installed = 0;
static int g_installAttempts = 0;

// --- UIDevice ---
static NSString *nd_hook_systemVersion(id self, SEL _cmd) {
    NDConfig *c = NDCurrentConfig();
    if (c.enabled && c.spoofUIDevice && c.systemVersion.length) return c.systemVersion;
    return ((NSString *(*)(id, SEL))nd_o_systemVersion)(self, _cmd);
}
static NSString *nd_hook_model(id self, SEL _cmd) {
    NDConfig *c = NDCurrentConfig();
    if (c.enabled && c.spoofUIDevice) return @"iPhone";
    return ((NSString *(*)(id, SEL))nd_o_model)(self, _cmd);
}
static NSString *nd_hook_localizedModel(id self, SEL _cmd) {
    NDConfig *c = NDCurrentConfig();
    if (c.enabled && c.spoofUIDevice) return @"iPhone";
    return ((NSString *(*)(id, SEL))nd_o_localizedModel)(self, _cmd);
}
static NSString *nd_hook_name(id self, SEL _cmd) {
    NDConfig *c = NDCurrentConfig();
    if (c.enabled && c.spoofUIDevice && c.kernHostname.length) return c.kernHostname;
    return ((NSString *(*)(id, SEL))nd_o_name)(self, _cmd);
}
static NSString *nd_hook_platform(id self, SEL _cmd) {
    NDConfig *c = NDCurrentConfig();
    if (c.enabled && c.spoofUIDevice && c.hwMachine.length) return c.hwMachine;
    return nd_o_platform ? ((NSString *(*)(id, SEL))nd_o_platform)(self, _cmd) : c.realMachine;
}
static NSString *nd_hook_bdcPlatform(id self, SEL _cmd) {
    NDConfig *c = NDCurrentConfig();
    if (c.enabled && c.spoofBaiduSDK && c.marketingName.length) return c.marketingName;
    return nd_o_bdcPlatform ? ((NSString *(*)(id, SEL))nd_o_bdcPlatform)(self, _cmd) : @"iPhone";
}
static NSString *nd_hook_bbaSysVer(id self, SEL _cmd) {
    NDConfig *c = NDCurrentConfig();
    if (c.enabled && c.spoofBaiduSDK && c.systemVersion.length) return c.systemVersion;
    return nd_o_bbaSysVer ? ((NSString *(*)(id, SEL))nd_o_bbaSysVer)(self, _cmd)
                          : UIDevice.currentDevice.systemVersion;
}
static NSUUID *nd_hook_idfv(id self, SEL _cmd) {
    NDConfig *c = NDCurrentConfig();
    if (c.enabled && c.spoofIDFV && c.idfv.length) {
        NSUUID *u = [[NSUUID alloc] initWithUUIDString:c.idfv];
        if (u) return u;
    }
    return nd_o_idfv ? ((NSUUID *(*)(id, SEL))nd_o_idfv)(self, _cmd)
                     : [UIDevice currentDevice].identifierForVendor;
}

// --- SAPIDeviceInfoHelper ---
static NSString *nd_hook_sapiDeviceModel(id self, SEL _cmd) {
    NDConfig *c = NDCurrentConfig();
    if (c.enabled && c.spoofBaiduSDK && c.hwMachine.length) return c.hwMachine;
    return nd_o_sapiDeviceModel ? ((NSString *(*)(id, SEL))nd_o_sapiDeviceModel)(self, _cmd) : c.realMachine;
}
static NSString *nd_hook_sapiDeviceName(id self, SEL _cmd) {
    NDConfig *c = NDCurrentConfig();
    if (c.enabled && c.spoofBaiduSDK) return @"iPhone";
    return nd_o_sapiDeviceName ? ((NSString *(*)(id, SEL))nd_o_sapiDeviceName)(self, _cmd) : @"iPhone";
}
static NSString *nd_hook_sapiDeviceType(id self, SEL _cmd) {
    NDConfig *c = NDCurrentConfig();
    if (c.enabled && c.spoofBaiduSDK) return @"ios";
    return nd_o_sapiDeviceType ? ((NSString *(*)(id, SEL))nd_o_sapiDeviceType)(self, _cmd) : @"ios";
}
static id nd_hook_sapiPlain(id self, SEL _cmd, id interface) {
    id orig = nd_o_sapiPlain ? ((id (*)(id, SEL, id))nd_o_sapiPlain)(self, _cmd, interface) : nil;
    NDConfig *c = NDCurrentConfig();
    if (c.enabled && c.spoofBaiduSDK && [orig isKindOfClass:NSString.class]) {
        return NDRewriteSapiPlain(orig, c);
    }
    return orig;
}
static id nd_hook_sapiRetrieve(id self, SEL _cmd, id keys) {
    id orig = nd_o_sapiRetrieve ? ((id (*)(id, SEL, id))nd_o_sapiRetrieve)(self, _cmd, keys) : nil;
    NDConfig *c = NDCurrentConfig();
    if (c.enabled && c.spoofBaiduSDK && [orig isKindOfClass:NSDictionary.class]) {
        return NDRewriteDict(orig, c, YES);
    }
    return orig;
}
static id nd_hook_sapiGenerate(id self, SEL _cmd, id plain) {
    NDConfig *c = NDCurrentConfig();
    id fed = plain;
    if (c.enabled && c.spoofBaiduSDK && [plain isKindOfClass:NSString.class]) {
        fed = NDRewriteSapiPlain(plain, c);
    }
    return nd_o_sapiGenerate ? ((id (*)(id, SEL, id))nd_o_sapiGenerate)(self, _cmd, fed) : fed;
}

// --- BDPUserAgent ---
static id nd_hook_uaGet(id self, SEL _cmd) {
    id orig = nd_o_uaGet ? ((id (*)(id, SEL))nd_o_uaGet)(self, _cmd) : nil;
    NDConfig *c = NDCurrentConfig();
    if (!c.enabled || !c.spoofUA) return orig;
    if ([orig isKindOfClass:NSString.class]) return NDRewriteDeviceInfoLine(orig, c);
    if ([orig isKindOfClass:NSDictionary.class]) return NDRewriteDict(orig, c, NO);
    return orig;
}
static id nd_hook_uaCompose(id self, SEL _cmd, id origin, BOOL encode) {
    id orig = nd_o_uaCompose ? ((id (*)(id, SEL, id, BOOL))nd_o_uaCompose)(self, _cmd, origin, encode) : nil;
    NDConfig *c = NDCurrentConfig();
    if (c.enabled && c.spoofUA && [orig isKindOfClass:NSString.class]) {
        return NDRewriteUA(orig, c);
    }
    return orig;
}

// --- 安装器（类型编码校验 + 继承方法落本类 + 主队列串行） ---

static BOOL NDEncOK(Method m, char retFirst, int argc, const char *argKinds) {
    if (!m) return NO;
    const char *types = method_getTypeEncoding(m);
    if (!types || types[0] != retFirst) return NO;
    int n = method_getNumberOfArguments(m) - 2; // 去 self/_cmd
    if (n != argc) return NO;
    if (argc == 0) return YES;
    for (int i = 0; i < argc; i++) {
        char buf[8] = {0};
        method_getArgumentType(m, (unsigned)(i + 2), buf, sizeof(buf));
        // 去掉类型限定前缀（r/n/N/o/O/R/V/@? 等），取第一个主类型字符
        char first = buf[0];
        const char *p = buf;
        while (*p && strchr("rnNoORV@?", *p) && strlen(p) > 1) p++;
        first = *p;
        if (first != argKinds[i]) return NO;
    }
    return YES;
}

static void NDInstallOne(NSString *clsName, SEL sel, BOOL isClass,
                         char retFirst, int argc, const char *argKinds,
                         IMP newImp, IMP *outOrig) {
    if (*outOrig) return;
    Class cls = NSClassFromString(clsName);
    if (!cls) return;
    Class target = isClass ? object_getClass(cls) : cls;
    Method m = class_getInstanceMethod(target, sel);
    if (!m) return;
    if (!NDEncOK(m, retFirst, argc, argKinds)) return;
    IMP orig = method_getImplementation(m);
    const char *types = method_getTypeEncoding(m);
    if (class_addMethod(target, sel, newImp, types)) {
        // 继承方法已落本类并指向 newImp；原继承 IMP 即 orig，直接保存。
        *outOrig = orig;
    } else {
        *outOrig = method_setImplementation(m, newImp);
    }
    g_installed++;
}

static void NDInstallAll(void) {
    // UIDevice 实例方法（含 category：platform/bdc_platformString/bba_cachedSystemVersion）
    NDInstallOne(@"UIDevice", @selector(systemVersion), NO, '@', 0, "",
                 (IMP)nd_hook_systemVersion, &nd_o_systemVersion);
    NDInstallOne(@"UIDevice", @selector(model), NO, '@', 0, "",
                 (IMP)nd_hook_model, &nd_o_model);
    NDInstallOne(@"UIDevice", @selector(localizedModel), NO, '@', 0, "",
                 (IMP)nd_hook_localizedModel, &nd_o_localizedModel);
    NDInstallOne(@"UIDevice", @selector(name), NO, '@', 0, "",
                 (IMP)nd_hook_name, &nd_o_name);
    NDInstallOne(@"UIDevice", NSSelectorFromString(@"platform"), NO, '@', 0, "",
                 (IMP)nd_hook_platform, &nd_o_platform);
    NDInstallOne(@"UIDevice", NSSelectorFromString(@"bdc_platformString"), NO, '@', 0, "",
                 (IMP)nd_hook_bdcPlatform, &nd_o_bdcPlatform);
    NDInstallOne(@"UIDevice", NSSelectorFromString(@"bba_cachedSystemVersion"), NO, '@', 0, "",
                 (IMP)nd_hook_bbaSysVer, &nd_o_bbaSysVer);
    NDInstallOne(@"UIDevice", @selector(identifierForVendor), NO, '@', 0, "",
                 (IMP)nd_hook_idfv, &nd_o_idfv);

    // SAPIDeviceInfoHelper 类方法
    NDInstallOne(@"SAPIDeviceInfoHelper", NSSelectorFromString(@"deviceModel"), YES, '@', 0, "",
                 (IMP)nd_hook_sapiDeviceModel, &nd_o_sapiDeviceModel);
    NDInstallOne(@"SAPIDeviceInfoHelper", NSSelectorFromString(@"deviceName"), YES, '@', 0, "",
                 (IMP)nd_hook_sapiDeviceName, &nd_o_sapiDeviceName);
    NDInstallOne(@"SAPIDeviceInfoHelper", NSSelectorFromString(@"deviceType"), YES, '@', 0, "",
                 (IMP)nd_hook_sapiDeviceType, &nd_o_sapiDeviceType);
    NDInstallOne(@"SAPIDeviceInfoHelper", NSSelectorFromString(@"plainDeviceInfoWithInterface:"), YES,
                 '@', 1, "@", (IMP)nd_hook_sapiPlain, &nd_o_sapiPlain);
    NDInstallOne(@"SAPIDeviceInfoHelper", NSSelectorFromString(@"retrieveDeviceInfoForKeys:"), YES,
                 '@', 1, "@", (IMP)nd_hook_sapiRetrieve, &nd_o_sapiRetrieve);
    NDInstallOne(@"SAPIDeviceInfoHelper", NSSelectorFromString(@"generateDeviceInfoWithPlainString:"), YES,
                 '@', 1, "@", (IMP)nd_hook_sapiGenerate, &nd_o_sapiGenerate);

    // BDPUserAgent 实例方法
    NDInstallOne(@"BDPUserAgent", NSSelectorFromString(@"useagent_getDeviceInfo"), NO, '@', 0, "",
                 (IMP)nd_hook_uaGet, &nd_o_uaGet);
    NDInstallOne(@"BDPUserAgent", NSSelectorFromString(@"composeUserAgentParameterWithOrigin:shouldEncodeURI:"), NO,
                 '@', 2, "@B", (IMP)nd_hook_uaCompose, &nd_o_uaCompose);
}

static volatile int g_ndDrainQueued = 0;

static void NDScheduleRetry(void) {
    if (g_installAttempts >= 30) return;
    g_installAttempts++;
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.5 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        NDInstallAll();
        NDScheduleRetry();
    });
}

static void NDAddImageCB(const struct mach_header *mh, intptr_t slide) {
    if (__sync_lock_test_and_set(&g_ndDrainQueued, 1)) return;
    dispatch_async(dispatch_get_main_queue(), ^{
        __sync_lock_release(&g_ndDrainQueued);      // 原子复位，与 test_and_set 配对
        NDInstallAll();
    });
}


// ============================== 9.20-01 UA 出口改写（原生层，最终出口） ==============================
// 证据（NDProbe3 真机报告）：
//   - WAP 登录页（passport.baidu.com/cap/init）UA 经 NSMutableURLRequest UA 头下发；
//   - Sapi webview UA 经 -[WKWebView setCustomUserAgent:] 下发；
//   - 裸 Mozilla 前缀（CPU iPhone OS 16_3）源自 -[BDPUserAgent webViewDefaultUserAgent]；
//   - native 登录链（wappass.baidu.com /wp/api/login* 等）UA 不走 setValue:forHTTPHeaderField:，
//     在 dataTask 出口的请求头里可见，只能在 NSURLSession dataTask 出口堵。
// 全部为原生 ObjC swizzle，不注入 JS、不改网页内容；值统一过 NDRewriteUA，Mobile/15E148 永不触碰。

static _Thread_local int g_nduInRewrite = 0;

static Method NDUOwnMethod(Class cls, SEL sel) {
    if (!cls || !sel) return NULL;
    unsigned int count = 0;
    Method found = NULL;
    Method *list = class_copyMethodList(cls, &count);
    for (unsigned int i = 0; i < count; i++) {
        if (method_getName(list[i]) == sel) { found = list[i]; break; }
    }
    free(list);
    return found;
}

static BOOL NDUIsSubclassOrSame(Class cls, Class ancestor) {
    for (Class c = cls; c; c = class_getSuperclass(c)) if (c == ancestor) return YES;
    return NO;
}

// 手写安全 swizzle：继承方法先在本类落地；alias 必须由本次安装成功添加。
static BOOL NDUSwap(Class cls, SEL target, IMP tramp, SEL aliasSel, const char *types) {
    Method ownTarget = NDUOwnMethod(cls, target);
    if (ownTarget && method_getImplementation(ownTarget) == tramp)
        return NDUOwnMethod(cls, aliasSel) != NULL;
    Method m = class_getInstanceMethod(cls, target);
    if (!m) return NO;
    IMP orig = method_getImplementation(m);
    const char *realTypes = method_getTypeEncoding(m);
    if (!ownTarget && !class_addMethod(cls, target, orig, realTypes)) return NO;
    if (!class_addMethod(cls, aliasSel, tramp, types ?: realTypes)) return NO;
    Method tm = NDUOwnMethod(cls, target);
    Method am = NDUOwnMethod(cls, aliasSel);
    if (!tm || !am || method_getImplementation(am) != tramp) return NO;
    method_exchangeImplementations(tm, am);
    return method_getImplementation(tm) == tramp;
}

// 仅当 UA 仍含真机机型/系统/营销名标记时才改写，避免无谓复制请求。
static BOOL NDUAContainsReal(NSString *s, NDConfig *c) {
    if (![s isKindOfClass:NSString.class] || !s.length) return NO;
    if (c.realMachine.length &&
        ([s containsString:c.realMachine] || [s containsString:NDMachineEncoded(c.realMachine)]))
        return YES;
    if (c.realOSVersion.length && [s containsString:c.realOSVersion]) return YES;
    NSString *realUnder = [c.realOSVersion stringByReplacingOccurrencesOfString:@"." withString:@"_"];
    if (realUnder.length && [s containsString:[NSString stringWithFormat:@"OS %@ like", realUnder]])
        return YES;
    if (c.marketingName.length) {
        for (NSString *realMarketing in @[@"iPhoneSE2", @"iPhoneSE3", @"Unknown_iPhone"]) {
            if (![realMarketing isEqualToString:c.marketingName] &&
                [s containsString:[NSString stringWithFormat:@";%@;", realMarketing]])
                return YES;
        }
    }
    return NO;
}

static SEL g_nduSelWkSetUA = NULL;
static SEL g_nduSelWkDefaultUA = NULL;
static SEL g_nduSelSetHdr = NULL;
static SEL g_nduSelDt1 = NULL;
static SEL g_nduSelDt2 = NULL;
static SEL g_nduSelConn = NULL;

// 1) -[WKWebView setCustomUserAgent:]：改写入参再下发
static void ndu_tr_wkSetUA(id self, SEL _cmd, id ua) {
    id out = ua;
    NDConfig *c = NDCurrentConfig();
    if (c.enabled && c.spoofUA && [ua isKindOfClass:NSString.class] && NDUAContainsReal(ua, c))
        out = NDRewriteUA(ua, c);
    ((void(*)(id, SEL, id))objc_msgSend)(self, g_nduSelWkSetUA, out);
}

// 2) -[BDPUserAgent webViewDefaultUserAgent]：裸 Mozilla 前缀源头
static id ndu_tr_wkDefaultUA(id self, SEL _cmd) {
    id orig = ((id(*)(id, SEL))objc_msgSend)(self, g_nduSelWkDefaultUA);
    NDConfig *c = NDCurrentConfig();
    if (c.enabled && c.spoofUA && [orig isKindOfClass:NSString.class] && NDUAContainsReal(orig, c))
        return NDRewriteUA(orig, c);
    return orig;
}

// 3) -[NSMutableURLRequest setValue:forHTTPHeaderField:]：仅改写 User-Agent 头
static void ndu_tr_setHdr(id self, SEL _cmd, id value, id field) {
    id out = value;
    NDConfig *c = NDCurrentConfig();
    if (g_nduInRewrite == 0 && c.enabled && c.spoofUA &&
        [field isKindOfClass:NSString.class] &&
        [((NSString *)field).lowercaseString isEqualToString:@"user-agent"] &&
        [value isKindOfClass:NSString.class] && NDUAContainsReal(value, c)) {
        out = NDRewriteUA(value, c);
    }
    ((void(*)(id, SEL, id, id))objc_msgSend)(self, g_nduSelSetHdr, out, field);
}

// 4) NSURLSession dataTask 出口：复制请求并改写 UA 头（覆盖 native 登录链）
static NSURLRequest *NDURewriteRequest(NSURLRequest *req, NSURLSession *session, NDConfig *c) {
    if (g_nduInRewrite || !c.enabled || !c.spoofUA || ![req isKindOfClass:NSURLRequest.class])
        return req;
    __block NSString *ua = nil;
    [req.allHTTPHeaderFields enumerateKeysAndObjectsUsingBlock:^(id key, id obj, BOOL *stop) {
        if ([key isKindOfClass:NSString.class] &&
            [(NSString *)key caseInsensitiveCompare:@"User-Agent"] == NSOrderedSame &&
            [obj isKindOfClass:NSString.class]) {
            ua = obj;
            *stop = YES;
        }
    }];
    // 请求头没有时，再看 session 配置级 UA（HTTPAdditionalHeaders）
    if (![ua isKindOfClass:NSString.class] && session) {
        @try {
            id sh = session.configuration.HTTPAdditionalHeaders[@"User-Agent"];
            if ([sh isKindOfClass:NSString.class]) ua = sh;
        } @catch (__unused NSException *e) {}
    }
    if (![ua isKindOfClass:NSString.class] || !NDUAContainsReal(ua, c)) return req;
    NSString *newUA = NDRewriteUA(ua, c);
    if ([newUA isEqualToString:ua]) return req;
    NSMutableURLRequest *m = nil;
    g_nduInRewrite++;
    @try {
        m = [req mutableCopy];
        [m setValue:newUA forHTTPHeaderField:@"User-Agent"];
    } @catch (__unused NSException *e) {
        m = nil;
    } @finally {
        g_nduInRewrite--;
    }
    return m ?: req;
}

static id ndu_tr_dt1(id self, SEL _cmd, NSURLRequest *req) {
    NDConfig *c = NDCurrentConfig();
    NSURLRequest *r = NDURewriteRequest(req, (NSURLSession *)self, c);
    return ((id(*)(id, SEL, id))objc_msgSend)(self, g_nduSelDt1, r);
}
static id ndu_tr_dt2(id self, SEL _cmd, NSURLRequest *req, id handler) {
    NDConfig *c = NDCurrentConfig();
    NSURLRequest *r = NDURewriteRequest(req, (NSURLSession *)self, c);
    return ((id(*)(id, SEL, id, id))objc_msgSend)(self, g_nduSelDt2, r, handler);
}
static void ndu_tr_conn(id cls, SEL _cmd, NSURLRequest *req, id queue, id handler) {
    NDConfig *c = NDCurrentConfig();
    NSURLRequest *r = NDURewriteRequest(req, nil, c);
    ((void(*)(id, SEL, id, id, id))objc_msgSend)(cls, g_nduSelConn, r, queue, handler);
}

static BOOL g_nduStarted = NO;
static int g_nduTries = 0;

static void NDUScanPass(void) {
    @try {
        // 1. WKWebView setCustomUserAgent:
        Class wk = NSClassFromString(@"WKWebView");
        if (wk) {
            Method m = NDUOwnMethod(wk, @selector(setCustomUserAgent:));
            if (m) NDUSwap(wk, @selector(setCustomUserAgent:), (IMP)ndu_tr_wkSetUA,
                           g_nduSelWkSetUA, method_getTypeEncoding(m));
        }
        // 2. BDPUserAgent webViewDefaultUserAgent（裸前缀源头）
        Class bdp = NSClassFromString(@"BDPUserAgent");
        if (bdp) {
            SEL s = NSSelectorFromString(@"webViewDefaultUserAgent");
            Method m = NDUOwnMethod(bdp, s);
            if (m) NDUSwap(bdp, s, (IMP)ndu_tr_wkDefaultUA, g_nduSelWkDefaultUA,
                           method_getTypeEncoding(m));
        }
        // 3. NSMutableURLRequest 类簇：临时实例定位具体实现类
        Class reqCls = NSClassFromString(@"NSMutableURLRequest");
        if (reqCls) {
            @try {
                NSMutableURLRequest *tmp = [[NSMutableURLRequest alloc]
                    initWithURL:[NSURL URLWithString:@"http://127.0.0.1/"]];
                Class concrete = object_getClass(tmp);
                Method m = NDUOwnMethod(concrete, @selector(setValue:forHTTPHeaderField:));
                if (m) NDUSwap(concrete, @selector(setValue:forHTTPHeaderField:),
                               (IMP)ndu_tr_setHdr, g_nduSelSetHdr, method_getTypeEncoding(m));
                if (concrete != reqCls) {
                    Method m2 = NDUOwnMethod(reqCls, @selector(setValue:forHTTPHeaderField:));
                    if (m2) NDUSwap(reqCls, @selector(setValue:forHTTPHeaderField:),
                                    (IMP)ndu_tr_setHdr, g_nduSelSetHdr, method_getTypeEncoding(m2));
                }
            } @catch (__unused NSException *e) {}
        }
        // 4. NSURLSession 及其子类（类簇扫描）
        Class sess = NSClassFromString(@"NSURLSession");
        if (sess) {
            unsigned int n = 0;
            Class *classes = objc_copyClassList(&n);
            if (classes) {
                for (unsigned int i = 0; i < n; i++) {
                    Class cc = classes[i];
                    if (!NDUIsSubclassOrSame(cc, sess)) continue;
                    Method m1 = NDUOwnMethod(cc, @selector(dataTaskWithRequest:));
                    if (m1) NDUSwap(cc, @selector(dataTaskWithRequest:),
                                    (IMP)ndu_tr_dt1, g_nduSelDt1, method_getTypeEncoding(m1));
                    Method m2 = NDUOwnMethod(cc, @selector(dataTaskWithRequest:completionHandler:));
                    if (m2) NDUSwap(cc, @selector(dataTaskWithRequest:completionHandler:),
                                    (IMP)ndu_tr_dt2, g_nduSelDt2, method_getTypeEncoding(m2));
                }
                free(classes);
            }
        }
        // NSURLConnection 异步类方法（metaclass）
        Class conn = NSClassFromString(@"NSURLConnection");
        if (conn) {
            Class meta = object_getClass(conn);
            Method m3 = NDUOwnMethod(meta, @selector(sendAsynchronousRequest:queue:completionHandler:));
            if (m3) NDUSwap(meta, @selector(sendAsynchronousRequest:queue:completionHandler:),
                            (IMP)ndu_tr_conn, g_nduSelConn, method_getTypeEncoding(m3));
        }
    } @catch (__unused NSException *e) {}
    if (++g_nduTries < 60)
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.5 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{ NDUScanPass(); });
}

static void NDInstallUAExits(void) {
    dispatch_async(dispatch_get_main_queue(), ^{
        if (g_nduStarted) return;
        g_nduStarted = YES;
        g_nduSelWkSetUA = sel_registerName("ndu_orig_wkSetUA:");
        g_nduSelWkDefaultUA = sel_registerName("ndu_orig_wkDefaultUA");
        g_nduSelSetHdr = sel_registerName("ndu_orig_setHdr::");
        g_nduSelDt1 = sel_registerName("ndu_orig_dt1:");
        g_nduSelDt2 = sel_registerName("ndu_orig_dt2::");
        g_nduSelConn = sel_registerName("ndu_orig_conn:::");
        NDUScanPass();
    });
}

static void NDStartObjCHooks(void) {
    dispatch_async(dispatch_get_main_queue(), ^{
        NDInstallAll();
        _dyld_register_func_for_add_image(NDAddImageCB);
        NDScheduleRetry();
        NDInstallUAExits();
    });
}

// ============================== PASS_CUSTOM 预置（免 Hook） ==============================

static void NDSeedPassCustom(NDConfig *c) {
    if (!c.enabled || !c.seedPassCustom) return;
    @try {
        NSUserDefaults *d = [NSUserDefaults standardUserDefaults];
        NSString *fakeUnder = [c.systemVersion stringByReplacingOccurrencesOfString:@"." withString:@"_"];
        NSString *realUnder = [c.realOSVersion stringByReplacingOccurrencesOfString:@"." withString:@"_"];

        // PASS_CUSTOM_SYS_VER：不存在或仍是真机值时写入
        NSString *sysVer = [d stringForKey:@"PASS_CUSTOM_SYS_VER"];
        if (!sysVer.length || [sysVer isEqualToString:c.realOSVersion]) {
            [d setObject:c.systemVersion forKey:@"PASS_CUSTOM_SYS_VER"];
        }
        // PASS_CUSTOM_UA_WK：不存在或仍含真机机型/系统时重写；Mobile/15E148 保持
        NSString *uaWk = [d stringForKey:@"PASS_CUSTOM_UA_WK"];
        BOOL stale = !uaWk.length ||
            (c.realMachine.length && ([uaWk containsString:c.realMachine] ||
                                      [uaWk containsString:NDMachineEncoded(c.realMachine)])) ||
            (realUnder.length && [uaWk containsString:[NSString stringWithFormat:@"OS %@ like", realUnder]]);
        if (stale) {
            NSString *appVer = [[NSBundle mainBundle] objectForInfoDictionaryKey:@"CFBundleShortVersionString"] ?: @"";
            NSArray<NSString *> *parts = [appVer componentsSeparatedByString:@"."];
            if (parts.count > 3) appVer = [[parts subarrayWithRange:NSMakeRange(0, 3)] componentsJoinedByString:@"."];
            NSString *sdkVer = c.passSdkVersion.length ? c.passSdkVersion : @"9.8.12.20";
            NSString *ua = [NSString stringWithFormat:
                @"Mozilla/5.0 (iPhone; CPU iPhone OS %@ like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 Sapi_%@/%@_%@_%@_Sapi",
                fakeUnder, sdkVer, appVer, NDMachineEncoded(c.hwMachine), c.systemVersion];
            [d setObject:ua forKey:@"PASS_CUSTOM_UA_WK"];
        }
        [d synchronize];
    } @catch (__unused NSException *e) {}
}

// ============================== 悬浮状态窗（只读自检） ==============================

static UIButton *g_floatBtn = nil;

static UIViewController *NDTopVC(void) {
    UIViewController *vc = UIApplication.sharedApplication.keyWindow.rootViewController;
    while (vc.presentedViewController) vc = vc.presentedViewController;
    while ([vc isKindOfClass:UINavigationController.class]) {
        vc = ((UINavigationController *)vc).visibleViewController;
    }
    return vc;
}

static void NDShowReport(void) {
    NDConfig *c = NDCurrentConfig();
    NSMutableString *r = [NSMutableString string];
    [r appendFormat:@"NDSpoofer 9.20-01\n\n"];
    [r appendFormat:@"总开关：%@\n", c.enabled ? @"开" : @"关"];
    [r appendFormat:@"C层(sysctl/uname)：%@\nUIDevice：%@\n百度SDK：%@\nUA：%@\nIDFV：%@\n磁盘：%@\nPASS_CUSTOM：%@\n",
        c.spoofSysctl ? @"开" : @"关", c.spoofUIDevice ? @"开" : @"关", c.spoofBaiduSDK ? @"开" : @"关",
        c.spoofUA ? @"开" : @"关", c.spoofIDFV ? @"开" : @"关", c.spoofStorage ? @"开" : @"关",
        c.seedPassCustom ? @"开" : @"关"];
    [r appendFormat:@"\n伪装机型：%@ (%@)\n营销名：%@\n伪装系统：%@ (%@)\n内存：%ldMB\n磁盘：%ldGB\n",
        c.hwMachine, c.hwModel, c.marketingName, c.systemVersion, c.systemBuild,
        (long)c.memorySizeMB, (long)c.diskSizeGB];
    [r appendFormat:@"\n真机机型：%@ (%@)\n真机系统：%@ (%@)\n真机内存：%lluMB\n真机磁盘：%lluGB\n",
        c.realMachine, c.realModel, c.realOSVersion, c.realBuild,
        c.realMemBytes / 1024 / 1024, c.realDiskBytes / 1024 / 1024 / 1024];
    [r appendFormat:@"\n已安装 Hook：%d 个\n", g_installed];
    NSUserDefaults *d = [NSUserDefaults standardUserDefaults];
    [r appendFormat:@"\nPASS_CUSTOM_SYS_VER：%@\n", [d stringForKey:@"PASS_CUSTOM_SYS_VER"] ?: @"(未设置)"];
    [r appendFormat:@"PASS_CUSTOM_UA_WK：%@\n", [d stringForKey:@"PASS_CUSTOM_UA_WK"] ?: @"(未设置)"];

    UIActivityViewController *ac = [[UIActivityViewController alloc] initWithActivityItems:@[r]
                                                                      applicationActivities:nil];
    UIViewController *top = NDTopVC();
    if (top) [top presentViewController:ac animated:YES completion:nil];
}

static void NDSetupFloatButton(void) {
    dispatch_async(dispatch_get_main_queue(), ^{
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3.0 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            if (g_floatBtn) return;
            CGRect f = [UIScreen mainScreen].bounds;
            UIButton *b = [UIButton buttonWithType:UIButtonTypeSystem];
            b.frame = CGRectMake(8, 120, 56, 56);
            b.layer.cornerRadius = 28;
            b.layer.masksToBounds = YES;
            b.backgroundColor = [UIColor colorWithRed:0.10 green:0.55 blue:0.95 alpha:0.85];
            b.titleLabel.font = [UIFont boldSystemFontOfSize:13];
            b.titleLabel.numberOfLines = 2;
            [b setTitle:@"网盘\n伪装" forState:UIControlStateNormal];
            [b setTitleColor:UIColor.whiteColor forState:UIControlStateNormal];
            [b addAction:[UIAction actionWithHandler:^(__unused UIAction *action) {
                NDShowReport();
            }] forControlEvents:UIControlEventTouchUpInside];
            b.autoresizingMask = UIViewAutoresizingFlexibleRightMargin | UIViewAutoresizingFlexibleBottomMargin;
            UIWindow *w = nil;
            for (UIScene *scene in UIApplication.sharedApplication.connectedScenes) {
                if ([scene isKindOfClass:UIWindowScene.class] && scene.activationState == UISceneActivationStateForegroundActive) {
                    for (UIWindow *win in ((UIWindowScene *)scene).windows) {
                        if (win.isKeyWindow) { w = win; break; }
                    }
                }
            }
            (void)f;
            if (w) {
                [w addSubview:b];
                g_floatBtn = b;
            }
        });
    });
}

// ============================== 入口 ==============================

static BOOL NDShouldRun(void) {
    NSString *bid = [[NSBundle mainBundle] bundleIdentifier] ?: @"";
    if (![bid isEqualToString:NDBundleID]) return NO;
    NSString *exePath = [[NSBundle mainBundle] executablePath] ?: @"";
    if ([exePath containsString:@".appex"] || [exePath containsString:@"/PlugIns/"]) return NO;
    return YES;
}

__attribute__((constructor))
static void nd_constructor(void) {
    @autoreleasepool {
        if (!NDShouldRun()) return;
        NDLoadConfig();
        NDConfig *c = NDCurrentConfig();
        if (!c.enabled) return;
        NDSeedPassCustom(c);
        NDStartObjCHooks();
        NDSetupFloatButton();

        // 管理器在 App 冷启动前写配置；回到前台时再读一次，兼容换容器后重启场景。
        [[NSNotificationCenter defaultCenter] addObserverForName:UIApplicationWillEnterForegroundNotification
                                                          object:nil queue:NSOperationQueue.mainQueue
                                                      usingBlock:^(__unused NSNotification *note) {
            NDLoadConfig();
        }];
        NSLog(@"[NDSpoofer] loaded profile=%@ (%@) iOS %@",
              c.hwMachine, c.hwModel, c.systemVersion);
    }
}
