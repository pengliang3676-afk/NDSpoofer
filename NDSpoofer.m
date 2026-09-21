//
//  NDSpoofer.m  —  百度网盘（com.baidu.netdisk）设备指纹伪装 dylib（卐解）
//
//  版本：9.21-06
//
//  9.21-06：悬浮球放到独立 UIWindow（不抢 keyWindow），验证码弹层关掉后球还在；点击空白穿透。
//
//  9.21-05：悬浮球标题改为「网解」；只在 SAPI 登录成功回调后等 15 秒再收边。
//  等验证码、短信页、登录 WebView 期间不算登录，球保持展开。登出后重新展开。
//
//  9.21-04：账号与安全→登录设备仍「未知设备」（设置→设备管理已是 iPhone15Pro）。
//  登录页在 PASSWebView（自有 loadRequest / initWKWebView），常用非持久 WKWebsiteDataStore，
//  只同步 defaultDataStore / 只 hook WKWebView 会漏。改为：PASSWebView 创建与导航时写入
//  该 WebView 的 cookie store；补 .baidu.com 域 DVIF；notAllowedGetDI 放开；device_name 强制 iPhone。
//  不注入 JS、不改 DOM。
//
//  9.21-03：H5 短信登录（13.34.0 真机：不走 smsWap，设备列表仍「未知设备」）。
//  NSHTTPCookieStorage 里已有 DVIF，但 WKWebView 用独立 WKHTTPCookieStore。
//  登录 POST 发出前把 DVIF 同步进该 WebView 的 cookie store，并补到 loadRequest 的 Cookie 头。
//  不注入 JS、不改 DOM。
//
//  9.21-02：悬浮球不再直接弹系统分享，改为在屏幕内弹出可滚动的自检报告卡片
//  （可直接查看 / 复制 / 转发，点遮罩或关闭按钮收起）；管理器与悬浮球名称统一改为“网解”。
//
//  9.21-01 新增（13.33.6 解密二进制反汇编证据：Passport 登录层不读屏幕，屏幕只进百度移动统计
//  EBAppLogDeviceHelper 的 +resolution / +resolutionString / +screenScale；而 UIScreen.bounds 被
//  1406 个函数就地实读，改全局 UIScreen 必致布局卡死/触摸失效）：仅 hook 上述三个统计类方法，
//  只改上报值、绝不触碰 UIScreen；机型池扩到 36 套异屏机型，每套屏幕/内存/磁盘/系统自洽。
//
//  9.20-03 新增（NDProbe4 证据：NADSplash 启动日志 / sofire 风控经 NSProcessInfo 读取真机
//  物理内存与系统版本，绕过 sysctl 与 UIDevice hook，造成 di 与启动日志/风控的内存、系统
//  版本跨通道矛盾，服务端设备管理页据此判“未知设备”）：
//   6. hook NSProcessInfo physicalMemory / operatingSystemVersion / operatingSystemVersionString；
//   7. NSUserDefaults setObject:forKey: 出口收口（NADSplash、sofire dvlwfrqupdt、UA 缓存键）；
//   8. 悬浮窗自检显示 NSProcessInfo 与 NADSplash/sofire/UA 实际值，便于真机核验。
//
//  9.20-04 修正：按 NDProbe4 实测，NADSplash 的 disk 与 sofire 的 dsks 均为 NSString 字节串
//  （非 NSNumber），统一按字符串类型收口，且仅在容量档位与真机不同时才替换；iPhone 8 与真机
//  同为 64GB 时保持原值，天然自洽。
//
//  9.20-05 修正（真机自检证据）：9.20-03/04 的 NSUserDefaults 出口与 UIDevice 等 hook 装在主队列
//  async，晚于 NADSplash/sofire/UA 缓存的启动期首次写入，导致真机 16.3/3GB 落盘（自检中
//  NSProcessInfo 已伪装但 NADSplash.systemVersion、sofire.hwphysm、NAD UA、BBA Check 仍为真机值）。
//  现把 NDInstallAll（UIDevice/NSProcessInfo/SAPI/BDPUserAgent）与 NSUserDefaults 出口全部提前到
//  constructor 同步安装（与探针 NDProbe4 的 +load 抢早时机一致），主队列仅保留 dyld 回调与重试兜底。
//
//  设计原则（与探针 NDProbe2/NDProbe3 证据一一对应）：
//   1. 只在 com.baidu.netdisk 主进程生效，扩展（.appex/PlugIns）不生效。
//   2. 只走原生层：sysctl/uname/statfs C 层 interpose + Objective-C runtime swizzle，
//      绝不注入 JS、不改网页 DOM/JS 环境、不动 Mobile/15E148。
//   2a. 9.20-01 新增原生 UA 出口改写（非 JS）：WKWebView setCustomUserAgent:、
//      BDPUserAgent webViewDefaultUserAgent、NSMutableURLRequest UA 头、
//      NSURLSession dataTask 出口；覆盖 WAP 登录页与 native 登录链。
//   3. 9.21-01 起机型池扩到异屏机型；屏幕只改百度统计 EBAppLogDeviceHelper 的上报值
//      （resolution/resolutionString/screenScale），绝不 hook UIScreen，布局仍用真机尺寸，
//      从根上避免改全局屏幕导致的布局卡死/触摸失效。
//   4. 不碰 App 版本、Sapi SDK 版本、tpl、cuid/utdid/deviceID、TeamID、运营商（默认）。
//   5. 任何开关关闭或配置缺失一律透传原实现；hook 安装前做类型编码校验，不匹配就不装。
//
//  配置文件：容器 Documents/ndspoofer_config.plist（由“网解”管理器逐容器写入）。
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
@property(nonatomic, assign) BOOL spoofScreen;
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
@property(nonatomic, assign) CGFloat screenWidth;
@property(nonatomic, assign) CGFloat screenHeight;
@property(nonatomic, assign) CGFloat nativeScreenWidth;
@property(nonatomic, assign) CGFloat nativeScreenHeight;
@property(nonatomic, assign) CGFloat screenScale;
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
static double NDCfgDouble(NSDictionary *d, NSString *key, double def) {
    id v = d[key];
    return [v isKindOfClass:NSNumber.class] ? [v doubleValue] : def;
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
        c.spoofScreen      = NDCfgBool(d, @"spoofScreen", NO);
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
        c.screenWidth        = NDCfgDouble(d, @"screenWidth", 0);
        c.screenHeight       = NDCfgDouble(d, @"screenHeight", 0);
        c.nativeScreenWidth  = NDCfgDouble(d, @"nativeScreenWidth", 0);
        c.nativeScreenHeight = NDCfgDouble(d, @"nativeScreenHeight", 0);
        c.screenScale        = NDCfgDouble(d, @"screenScale", 0);
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

// SAPI 明文设备串以 \x01（SOH）分隔，字段顺序固定（deviceInfoKeyMapper）：
// [3] PhoneModel、[4] SystemVersion、[20] ram(KB)、[21] internal_memory(KB)。
// 9.20-02 修正：旧版误按空格切分，真机明文无空格导致整体 no-op，内存/磁盘从未改写，
// 上报 iPhone10,1（iPhone 8/2GB）却带真机 3GB 内存，服务端设备管理页据此判“未知设备”。
static NSString *NDRewriteSapiPlain(NSString *s, NDConfig *c) {
    if (![s isKindOfClass:NSString.class] || !s.length) return s;
    NSString *sep = @"\x01";
    if ([s rangeOfString:sep].location == NSNotFound) return s;
    NSMutableArray<NSString *> *f = [[s componentsSeparatedByString:sep] mutableCopy];
    if (f.count < 22) return s; // 字段结构不符预期，原样返回，绝不误改

    // [3] PhoneModel：兜底（底层 UIDevice/SAPI hook 通常已改）
    if (c.hwMachine.length && f[3].length && ![f[3] isEqualToString:c.hwMachine]) {
        f[3] = c.hwMachine;
    }
    // [4] SystemVersion：仅当是 数字.数字[.数字] 形态才改
    if (c.systemVersion.length && f[4].length) {
        NSRegularExpression *verRx = [NSRegularExpression regularExpressionWithPattern:
            @"^\\d+\\.\\d+(?:\\.\\d+)?$" options:0 error:nil];
        if ([verRx firstMatchInString:f[4] options:0 range:NSMakeRange(0, f[4].length)]) {
            f[4] = c.systemVersion;
        }
    }
    // [20] ram：总内存（KB）。iPhone 8 物理内存 2GB，真机 SE2 为 3GB，
    // 这是设备管理页判定“未知设备”的核心矛盾，必须按机型改写。
    if (c.memorySizeMB > 0 && f[20].length &&
        [f[20] rangeOfString:@"^\\d+$" options:NSRegularExpressionSearch].location != NSNotFound) {
        f[20] = [NSString stringWithFormat:@"%ld", (long)c.memorySizeMB * 1024L];
    }
    // [21] internal_memory：总磁盘（KB）。仅当档案容量档位与真机不同时才改；
    // 机型池固定 iPhone 8 为 64GB、真机同为 64GB 时保持原值（真实文件系统总容量），天然自洽。
    if (c.diskSizeGB > 0 && c.realDiskBytes > 0 && f[21].length &&
        [f[21] rangeOfString:@"^\\d+$" options:NSRegularExpressionSearch].location != NSNotFound) {
        uint64_t realDiskGB = (c.realDiskBytes + 500000000ULL) / 1000000000ULL;
        if ((NSInteger)realDiskGB != c.diskSizeGB) {
            f[21] = [NSString stringWithFormat:@"%lld", (long long)c.diskSizeGB * 1024LL * 1024LL];
        }
    }
    return [f componentsJoinedByString:sep];
}

// ============================== NSUserDefaults 出口收口（NADSplash / sofire / UA 缓存） ==============================
// 这些通道在启动时把设备信息打包成字典或 UA 字符串写入 NSUserDefaults，再经网络上报；
// 即使 NSProcessInfo hook 已改源头，仍可能在 hook 安装前构造、或走内部缓存，故在 setObject 出口兜底。
// 仅按白名单 key 处理，其余一律原样透传。

// 按原始 NSNumber 的整型类型写入伪装内存字节数，保持与 App 自身编码一致（sofire 为 int32 截断）。
static NSNumber *NDFakeMemNumber(NSNumber *orig, uint64_t fakeBytes) {
    const char *t = orig.objCType ?: "";
    switch (t[0]) {
        case 'i': return [NSNumber numberWithInt:(int32_t)(uint32_t)fakeBytes];
        case 'I': return [NSNumber numberWithUnsignedInt:(uint32_t)fakeBytes];
        case 'l': return [NSNumber numberWithLong:(long)fakeBytes];
        case 'L': return [NSNumber numberWithUnsignedLong:(unsigned long)fakeBytes];
        case 'q': return [NSNumber numberWithLongLong:(int64_t)fakeBytes];
        case 'Q': return [NSNumber numberWithUnsignedLongLong:fakeBytes];
        case 's': return [NSNumber numberWithShort:(int16_t)(uint16_t)fakeBytes];
        case 'S': return [NSNumber numberWithUnsignedShort:(uint16_t)fakeBytes];
        default:  return [NSNumber numberWithLongLong:(int64_t)fakeBytes];
    }
}

// NADSplashLatestLogFormationKeyName：systemVersion、physicalMemory、disk 均为 NSString 明文。
static NSDictionary *NDRewriteSplashDict(NSDictionary *d, NDConfig *c) {
    NSMutableDictionary *m = d.mutableCopy;
    if (c.systemVersion.length) {
        id sv = m[@"systemVersion"];
        if ([sv isKindOfClass:NSString.class]) m[@"systemVersion"] = c.systemVersion;
    }
    if (c.memorySizeMB > 0) {
        id pm = m[@"physicalMemory"];
        if ([pm isKindOfClass:NSString.class])
            m[@"physicalMemory"] = [NSString stringWithFormat:@"%llu", (uint64_t)c.memorySizeMB * 1024ULL * 1024ULL];
    }
    // disk 为磁盘字节字符串；仅当档案容量档位与真机不同才替换（iPhone 8 与真机同为 64GB 时保持原值）
    if (c.diskSizeGB > 0 && c.realDiskBytes > 0) {
        id dk = m[@"disk"];
        uint64_t realDiskGB = (c.realDiskBytes + 500000000ULL) / 1000000000ULL;
        if ([dk isKindOfClass:NSString.class] && (NSInteger)realDiskGB != c.diskSizeGB)
            m[@"disk"] = [NSString stringWithFormat:@"%lld", (long long)c.diskSizeGB * 1024LL * 1024LL * 1024LL];
    }
    return m;
}

// dvlwfrqupdt（sofire）：hwphysm 为 NSNumber（int32 截断），dsks 为 NSString 磁盘字节（仅档位不同才改）。
static NSDictionary *NDRewriteSofireDict(NSDictionary *d, NDConfig *c) {
    NSMutableDictionary *m = d.mutableCopy;
    if (c.memorySizeMB > 0) {
        id pm = m[@"hwphysm"];
        if ([pm isKindOfClass:NSNumber.class])
            m[@"hwphysm"] = NDFakeMemNumber(pm, (uint64_t)c.memorySizeMB * 1024ULL * 1024ULL);
    }
    if (c.diskSizeGB > 0 && c.realDiskBytes > 0) {
        id dsk = m[@"dsks"];
        uint64_t realDiskGB = (c.realDiskBytes + 500000000ULL) / 1000000000ULL;
        if ([dsk isKindOfClass:NSString.class] && (NSInteger)realDiskGB != c.diskSizeGB)
            m[@"dsks"] = [NSString stringWithFormat:@"%lld", (long long)c.diskSizeGB * 1024LL * 1024LL * 1024LL];
    }
    return m;
}

// BBAUserAgentCheckInfoKey 形态为 “_iPhone10,1_16.3”（机型_版本），尾部版本段替换；其余 UA 走通用改写。
static NSString *NDRewriteCachedUA(NSString *s, NDConfig *c, BOOL isCheckInfo) {
    if (![s isKindOfClass:NSString.class] || !s.length) return s;
    if (isCheckInfo) {
        NSRange under = [s rangeOfString:@"_" options:NSBackwardsSearch];
        if (under.location == NSNotFound || under.location + 1 >= s.length) return s;
        NSString *tail = [s substringFromIndex:under.location];
        NSRegularExpression *rx = [NSRegularExpression regularExpressionWithPattern:@"^_\\d+(?:\\.\\d+)+$"
                                                                           options:0 error:nil];
        if (![rx firstMatchInString:tail options:0 range:NSMakeRange(0, tail.length)]) return s;
        return [[s substringToIndex:under.location] stringByAppendingFormat:@"_%@", c.systemVersion];
    }
    // 仅当仍含真机机型/系统标记时才改写，避免对无关 UA 误改
    BOOL needs = NO;
    if (c.realMachine.length &&
        ([s containsString:c.realMachine] || [s containsString:NDMachineEncoded(c.realMachine)]))
        needs = YES;
    if (c.realOSVersion.length && [s containsString:c.realOSVersion]) needs = YES;
    NSString *realUnder = [c.realOSVersion stringByReplacingOccurrencesOfString:@"." withString:@"_"];
    if (realUnder.length && [s containsString:[NSString stringWithFormat:@"OS %@ like", realUnder]])
        needs = YES;
    return needs ? NDRewriteUA(s, c) : s;
}

// 按 key 白名单分发；非目标 key 返回原值。
static id NDRewriteDefaultsValue(NSString *key, id value, NDConfig *c) {
    if (![key isKindOfClass:NSString.class]) return value;
    if ([key isEqualToString:@"NADSplashLatestLogFormationKeyName"]) {
        if ([value isKindOfClass:NSDictionary.class]) return NDRewriteSplashDict((NSDictionary *)value, c);
        return value;
    }
    if ([key isEqualToString:@"dvlwfrqupdt"]) {
        if ([value isKindOfClass:NSDictionary.class]) return NDRewriteSofireDict((NSDictionary *)value, c);
        return value;
    }
    if ([key isEqualToString:@"BBAUserAgentCheckInfoKey"]) {
        if ([value isKindOfClass:NSString.class]) return NDRewriteCachedUA(value, c, YES);
        return value;
    }
    static NSSet *uaKeys;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        uaKeys = [NSSet setWithArray:@[@"BBAUserAgentKey", @"GDTDefaultUA",
                                       @"NADCustomUserAgentKey", @"NADUserAgentKey"]];
    });
    if ([uaKeys containsObject:key] && [value isKindOfClass:NSString.class])
        return NDRewriteCachedUA(value, c, NO);
    return value;
}

// 字典白名单键：只改机型/系统版本承载键
static NSSet<NSString *> *NDSapiDictKeys(void) {
    static NSSet *keys;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        keys = [NSSet setWithArray:@[@"PhoneModel", @"phoneModel", @"SystemVersion",
                                     @"osVersion", @"systemVersion", @"model", @"machine",
                                     @"hwMachine", @"device_name"]];
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
            if (sapi && [k isEqualToString:@"device_name"]) {
                m[k] = @"iPhone";
            } else if (sapi && ([k isEqualToString:@"PhoneModel"] || [k isEqualToString:@"phoneModel"])) {
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
static IMP nd_o_sapiSetCookie = NULL;
static IMP nd_o_sapiNotAllowedDI = NULL;
static IMP nd_o_uaGet = NULL;
static IMP nd_o_uaCompose = NULL;
static IMP nd_o_physMem = NULL;       // NSProcessInfo physicalMemory
static IMP nd_o_osVerString = NULL;  // NSProcessInfo operatingSystemVersionString
static IMP nd_o_osVer = NULL;        // NSProcessInfo operatingSystemVersion（结构体返回）
static IMP nd_o_ebResolution = NULL;        // EBAppLogDeviceHelper +resolution（CGSize 结构体）
static IMP nd_o_ebResolutionString = NULL;  // EBAppLogDeviceHelper +resolutionString
static IMP nd_o_ebScreenScale = NULL;       // EBAppLogDeviceHelper +screenScale
static IMP nd_o_handleLogin = NULL;
static IMP nd_o_web2Native = NULL;
static IMP nd_o_loginSuccessful = NULL;
static IMP nd_o_logoutCurrent = NULL;

static void NDFloatOnLoginSuccess(void);
static void NDFloatOnLogout(void);

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

// --- NSProcessInfo（NADSplash 启动日志 / sofire 风控的物理内存与系统版本来源；
//     这两个通道不走 sysctl / UIDevice，9.20-02 前漏改，上报真机 3GB 与 16.3） ---
static unsigned long long nd_hook_physMem(id self, SEL _cmd) {
    NDConfig *c = NDCurrentConfig();
    if (c.enabled && c.spoofBaiduSDK && c.memorySizeMB > 0)
        return (unsigned long long)c.memorySizeMB * 1024ULL * 1024ULL;
    // 原 IMP 缺失时回真机基线，禁止再调 .physicalMemory（会递归回本 hook）
    return nd_o_physMem ? ((unsigned long long (*)(id, SEL))nd_o_physMem)(self, _cmd)
                       : c.realMemBytes;
}
static NSString *nd_hook_osVerString(id self, SEL _cmd) {
    NDConfig *c = NDCurrentConfig();
    if (c.enabled && c.spoofBaiduSDK && c.systemVersion.length) {
        NSString *build = c.systemBuild.length ? c.systemBuild : @"";
        return [NSString stringWithFormat:@"Version %@ (Build %@)", c.systemVersion, build];
    }
    return nd_o_osVerString ? ((NSString *(*)(id, SEL))nd_o_osVerString)(self, _cmd)
                           : (c.realOSVersion.length ? c.realOSVersion : @"");
}
// NSOperatingSystemVersion 为 24 字节（3×NSInteger），arm64 走 sret；
// 函数指针按“返回该结构体”声明，编译器自动应用 sret ABI，禁止改成返回标量。
static NSOperatingSystemVersion nd_hook_osVer(id self, SEL _cmd) {
    NDConfig *c = NDCurrentConfig();
    if (c.enabled && c.spoofBaiduSDK && c.systemVersion.length) {
        NSArray<NSString *> *p = [c.systemVersion componentsSeparatedByString:@"."];
        NSOperatingSystemVersion v = {0, 0, 0};
        if (p.count >= 1) v.majorVersion = [p[0] integerValue];
        if (p.count >= 2) v.minorVersion = [p[1] integerValue];
        if (p.count >= 3) v.patchVersion = [p[2] integerValue];
        return v;
    }
    if (nd_o_osVer) {
        return ((NSOperatingSystemVersion (*)(id, SEL))nd_o_osVer)(self, _cmd);
    }
    NSOperatingSystemVersion z = {0, 0, 0};
    return z;
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
static BOOL nd_hook_sapiNotAllowedDI(id self, SEL _cmd, unsigned long long idx) {
    NDConfig *c = NDCurrentConfig();
    if (c && c.enabled && c.spoofBaiduSDK) return NO;
    return nd_o_sapiNotAllowedDI
        ? ((BOOL (*)(id, SEL, unsigned long long))nd_o_sapiNotAllowedDI)(self, _cmd, idx)
        : NO;
}

static void nd_hook_handleLogin(id self, SEL _cmd, id model, id extra) {
    if (nd_o_handleLogin)
        ((void (*)(id, SEL, id, id))nd_o_handleLogin)(self, _cmd, model, extra);
    NDFloatOnLoginSuccess();
}
static void nd_hook_web2Native(id self, SEL _cmd, id model) {
    if (nd_o_web2Native)
        ((void (*)(id, SEL, id))nd_o_web2Native)(self, _cmd, model);
    NDFloatOnLoginSuccess();
}
static void nd_hook_loginSuccessful(id self, SEL _cmd) {
    if (nd_o_loginSuccessful)
        ((void (*)(id, SEL))nd_o_loginSuccessful)(self, _cmd);
    NDFloatOnLoginSuccess();
}
static BOOL nd_hook_logoutCurrent(id self, SEL _cmd) {
    BOOL r = nd_o_logoutCurrent ? ((BOOL (*)(id, SEL))nd_o_logoutCurrent)(self, _cmd) : NO;
    NDFloatOnLogout();
    return r;
}

static int g_ndInSetCookie = 0;

static NSArray<NSHTTPCookie *> *NDDVIFCookiesFromShared(void) {
    NSHTTPCookieStorage *st = [NSHTTPCookieStorage sharedHTTPCookieStorage];
    NSMutableArray *out = [NSMutableArray array];
    NSMutableSet *seen = [NSMutableSet set];
    NSArray *all = nil;
    @try { all = [st cookies]; } @catch (__unused NSException *e) { all = nil; }
    for (NSHTTPCookie *c in all) {
        if (![c isKindOfClass:NSHTTPCookie.class]) continue;
        if (![c.name isEqualToString:@"DVIF"] || !c.value.length) continue;
        NSString *k = [NSString stringWithFormat:@"%@|%@|%@", c.domain ?: @"", c.path ?: @"", c.name];
        if ([seen containsObject:k]) continue;
        [seen addObject:k];
        [out addObject:c];
        NSDictionary *props = c.properties;
        if (![props isKindOfClass:NSDictionary.class]) continue;
        for (NSString *dom in @[ @".baidu.com", @"baidu.com" ]) {
            if ([c.domain isEqualToString:dom]) continue;
            NSString *k2 = [NSString stringWithFormat:@"%@|%@|DVIF", dom, c.path ?: @"/"];
            if ([seen containsObject:k2]) continue;
            NSMutableDictionary *p = [props mutableCopy];
            p[NSHTTPCookieDomain] = dom;
            if (![p[NSHTTPCookiePath] isKindOfClass:NSString.class] || ![p[NSHTTPCookiePath] length])
                p[NSHTTPCookiePath] = @"/";
            p[NSHTTPCookieSecure] = @"TRUE";
            NSHTTPCookie *n = [NSHTTPCookie cookieWithProperties:p];
            if (!n) continue;
            [seen addObject:k2];
            [out addObject:n];
        }
    }
    return out;
}

static void NDSyncDVIFToStore(id store, void (^done)(void)) {
    void (^finish)(void) = ^{
        if (!done) return;
        if ([NSThread isMainThread]) done();
        else dispatch_async(dispatch_get_main_queue(), done);
    };
    if (!store) { finish(); return; }
    NSArray *cks = NDDVIFCookiesFromShared();
    SEL setSel = @selector(setCookie:completionHandler:);
    if (!cks.count || ![store respondsToSelector:setSel]) { finish(); return; }
    dispatch_group_t grp = dispatch_group_create();
    for (NSHTTPCookie *c in cks) {
        dispatch_group_enter(grp);
        ((void (*)(id, SEL, id, void (^)(void)))objc_msgSend)(store, setSel, c, ^{
            dispatch_group_leave(grp);
        });
    }
    dispatch_group_notify(grp, dispatch_get_main_queue(), finish);
}

static NSURLRequest *NDRequestAppendingDVIFCookie(NSURLRequest *req) {
    if (![req isKindOfClass:NSURLRequest.class]) return req;
    NSArray *cks = NDDVIFCookiesFromShared();
    if (!cks.count) return req;
    NSString *old = nil;
    for (NSString *k in req.allHTTPHeaderFields) {
        if ([k caseInsensitiveCompare:@"Cookie"] == NSOrderedSame) {
            old = req.allHTTPHeaderFields[k];
            break;
        }
    }
    NSMutableArray *parts = [NSMutableArray array];
    if (old.length) [parts addObject:old];
    BOOL added = NO;
    for (NSHTTPCookie *c in cks) {
        NSString *mark = [c.name stringByAppendingString:@"="];
        if (old.length && [old containsString:mark]) continue;
        [parts addObject:[NSString stringWithFormat:@"%@=%@", c.name, c.value]];
        added = YES;
    }
    if (!added) return req;
    NSMutableURLRequest *m = [req mutableCopy];
    [m setValue:[parts componentsJoinedByString:@"; "] forHTTPHeaderField:@"Cookie"];
    return m;
}

static BOOL NDRequestHasDVIF(NSURLRequest *req) {
    if (![req isKindOfClass:NSURLRequest.class]) return NO;
    for (NSString *k in req.allHTTPHeaderFields) {
        if ([k caseInsensitiveCompare:@"Cookie"] != NSOrderedSame) continue;
        NSString *v = req.allHTTPHeaderFields[k];
        return [v containsString:@"DVIF="];
    }
    return NO;
}

static id NDRealWebView(id pass) {
    if (!pass) return nil;
    @try {
        SEL s = NSSelectorFromString(@"realWebView");
        if ([pass respondsToSelector:s])
            return ((id (*)(id, SEL))objc_msgSend)(pass, s);
    } @catch (__unused NSException *e) {}
    return nil;
}

static void NDEnsureDeviceCookie(void) {
    Class cm = NSClassFromString(@"SAPICookieManager");
    SEL setDvif = NSSelectorFromString(@"setDeviceInfoToCookie");
    if (cm && [cm respondsToSelector:setDvif])
        ((void (*)(id, SEL))objc_msgSend)(cm, setDvif);
}

static BOOL NDURLNeedsDVIF(NSURL *u) {
    NSString *h = u.host.lowercaseString ?: @"";
    return [h containsString:@"wappass"] || [h containsString:@"passport"] ||
           [h containsString:@"baidu"];
}

static id NDCookieStoreFromWebView(id wv) {
    id store = nil;
    @try {
        if (!wv || ![wv respondsToSelector:@selector(configuration)]) return nil;
        id cfg = ((id (*)(id, SEL))objc_msgSend)(wv, @selector(configuration));
        if (!cfg || ![cfg respondsToSelector:@selector(websiteDataStore)]) return nil;
        id ds = ((id (*)(id, SEL))objc_msgSend)(cfg, @selector(websiteDataStore));
        if (!ds || ![ds respondsToSelector:@selector(httpCookieStore)]) return nil;
        store = ((id (*)(id, SEL))objc_msgSend)(ds, @selector(httpCookieStore));
    } @catch (__unused NSException *e) { store = nil; }
    return store;
}

static void nd_hook_sapiSetCookie(id self, SEL _cmd) {
    if (nd_o_sapiSetCookie)
        ((void (*)(id, SEL))nd_o_sapiSetCookie)(self, _cmd);
    if (__sync_lock_test_and_set(&g_ndInSetCookie, 1)) return;
    Class wkds = NSClassFromString(@"WKWebsiteDataStore");
    if (wkds && [wkds respondsToSelector:@selector(defaultDataStore)]) {
        id ds = ((id (*)(id, SEL))objc_msgSend)(wkds, @selector(defaultDataStore));
        id store = ds ? ((id (*)(id, SEL))objc_msgSend)(ds, @selector(httpCookieStore)) : nil;
        NDSyncDVIFToStore(store, nil);
    }
    __sync_lock_release(&g_ndInSetCookie);
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

// operatingSystemVersion 返回 24 字节结构体（arm64 sret），单独安装并严格校验类型编码，
// 只在确为 3 个 64 位整型字段（{...=qqq}）时替换，避免结构体 ABI 错位。
static void NDInstallOSVersionStruct(void) {
    if (nd_o_osVer) return;
    Class cls = NSClassFromString(@"NSProcessInfo");
    if (!cls) return;
    SEL sel = @selector(operatingSystemVersion);
    Method m = class_getInstanceMethod(cls, sel);
    if (!m) return;
    const char *types = method_getTypeEncoding(m);
    if (!types || types[0] != '{') return;
    if (method_getNumberOfArguments(m) - 2 != 0) return;
    if (!strstr(types, "qqq")) return;
    nd_o_osVer = method_setImplementation(m, (IMP)nd_hook_osVer);
    g_installed++;
}

// --- EBAppLogDeviceHelper（百度移动统计 统一设备信息）屏幕出口 ---
// 仅改写上报值（物理分辨率 / 分辨率串 / 缩放倍数），绝不触碰 UIScreen，布局与触摸不受影响。
static BOOL NDScreenActive(NDConfig *c) {
    return c && c.enabled && c.spoofScreen &&
           c.screenWidth > 0 && c.screenHeight > 0 && c.screenScale > 0;
}

// +resolution 原实现（13.33.6 反汇编确认）= bounds.width*scale × bounds.height*scale，
// 即“逻辑点×scale”的渲染像素，并非 nativeBounds。8 Plus/mini 面板有下采样，
// 渲染像素（如 1242×2208）≠面板物理像素（1080×1920），故必须同口径返回逻辑×scale。
// CGSize 为 {CGSize=dd}，16 字节，arm64 经 d0/d1 返回，无 sret。
static CGSize nd_hook_ebResolution(id self, SEL _cmd) {
    NDConfig *c = NDCurrentConfig();
    if (NDScreenActive(c)) {
        return CGSizeMake(c.screenWidth * c.screenScale,
                          c.screenHeight * c.screenScale);
    }
    if (nd_o_ebResolution) {
        return ((CGSize (*)(id, SEL))nd_o_ebResolution)(self, _cmd);
    }
    return CGSizeMake(0, 0);
}

// +screenScale 返回 double（2.0 / 3.0）。
static double nd_hook_ebScreenScale(id self, SEL _cmd) {
    NDConfig *c = NDCurrentConfig();
    if (NDScreenActive(c) && c.screenScale > 0) {
        return (double)c.screenScale;
    }
    if (nd_o_ebScreenScale) {
        return ((double (*)(id, SEL))nd_o_ebScreenScale)(self, _cmd);
    }
    return 2.0;
}

// +resolutionString：先调原实现拿到真机格式（如 750*1334），只替换前两组数字为目标物理像素，
// 分隔符与后缀保持原样，避免猜测格式串。
static NSString *nd_hook_ebResolutionString(id self, SEL _cmd) {
    NSString *orig = nd_o_ebResolutionString
        ? ((NSString *(*)(id, SEL))nd_o_ebResolutionString)(self, _cmd) : nil;
    NDConfig *c = NDCurrentConfig();
    if (!NDScreenActive(c)) return orig;
    if ([orig isKindOfClass:NSString.class] && orig.length) {
        NSRegularExpression *rx = [NSRegularExpression
            regularExpressionWithPattern:@"\\d+" options:0 error:nil];
        NSArray<NSTextCheckingResult *> *ms = [rx matchesInString:orig
                                                          options:0
                                                            range:NSMakeRange(0, orig.length)];
        if (ms.count >= 2) {
            NSMutableString *out = [orig mutableCopy];
            double rw = c.screenWidth * c.screenScale;
            double rh = c.screenHeight * c.screenScale;
            // 从后往前替换，避免 range 偏移；与 +resolution 同为逻辑×scale 口径。
            [out replaceCharactersInRange:ms[1].range
                                withString:[NSString stringWithFormat:@"%.0f", rh]];
            [out replaceCharactersInRange:ms[0].range
                                withString:[NSString stringWithFormat:@"%.0f", rw]];
            return out;
        }
    }
    return [NSString stringWithFormat:@"%.0f*%.0f",
            c.screenWidth * c.screenScale, c.screenHeight * c.screenScale];
}

// +resolution 为 CGSize 结构体返回，严格校验类型编码（{CGSize=dd}）与 0 参数后再替换。
static void NDInstallEBResolution(void) {
    if (nd_o_ebResolution) return;
    Class cls = NSClassFromString(@"EBAppLogDeviceHelper");
    if (!cls) return;
    SEL sel = NSSelectorFromString(@"resolution");
    Method m = class_getInstanceMethod(object_getClass(cls), sel);  // 类方法（元类）
    if (!m) m = class_getInstanceMethod(cls, sel);                  // 实例方法兜底
    if (!m) return;
    const char *types = method_getTypeEncoding(m);
    if (!types || types[0] != '{' || !strstr(types, "CGSize")) return;
    if (method_getNumberOfArguments(m) - 2 != 0) return;
    nd_o_ebResolution = method_setImplementation(m, (IMP)nd_hook_ebResolution);
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
    NDInstallOne(@"SAPICookieManager", NSSelectorFromString(@"setDeviceInfoToCookie"), YES,
                 'v', 0, "", (IMP)nd_hook_sapiSetCookie, &nd_o_sapiSetCookie);
    NDInstallOne(@"SAPIDeviceInfoHelper", NSSelectorFromString(@"notAllowedGetDI:"), YES,
                 'B', 1, "Q", (IMP)nd_hook_sapiNotAllowedDI, &nd_o_sapiNotAllowedDI);

    // 悬浮球收边：只认 SAPI 登录成功 / 登出，不拿 BDUSS、不拿验证码页当登录。
    NDInstallOne(@"SAPILoginService", NSSelectorFromString(@"handleLoginWithModel:extraInfo:"), NO,
                 'v', 2, "@@", (IMP)nd_hook_handleLogin, &nd_o_handleLogin);
    NDInstallOne(@"SAPILoginService", NSSelectorFromString(@"web2NativeLoginWithLoginModel:"), NO,
                 'v', 1, "@", (IMP)nd_hook_web2Native, &nd_o_web2Native);
    NDInstallOne(@"PASSWebViewController", NSSelectorFromString(@"loginSuccessful"), NO,
                 'v', 0, "", (IMP)nd_hook_loginSuccessful, &nd_o_loginSuccessful);
    NDInstallOne(@"SAPILoginService", NSSelectorFromString(@"logoutCurrentModel"), NO,
                 'B', 0, "", (IMP)nd_hook_logoutCurrent, &nd_o_logoutCurrent);

    // BDPUserAgent 实例方法
    NDInstallOne(@"BDPUserAgent", NSSelectorFromString(@"useagent_getDeviceInfo"), NO, '@', 0, "",
                 (IMP)nd_hook_uaGet, &nd_o_uaGet);
    NDInstallOne(@"BDPUserAgent", NSSelectorFromString(@"composeUserAgentParameterWithOrigin:shouldEncodeURI:"), NO,
                 '@', 2, "@B", (IMP)nd_hook_uaCompose, &nd_o_uaCompose);

    // NSProcessInfo：NADSplash 启动日志 / sofire 风控的物理内存与系统版本来源
    NDInstallOne(@"NSProcessInfo", @selector(physicalMemory), NO,
                 'Q', 0, "", (IMP)nd_hook_physMem, &nd_o_physMem);
    NDInstallOne(@"NSProcessInfo", @selector(operatingSystemVersionString), NO,
                 '@', 0, "", (IMP)nd_hook_osVerString, &nd_o_osVerString);
    NDInstallOSVersionStruct();

    // EBAppLogDeviceHelper：仅改写百度统计上报的物理分辨率/分辨率串/缩放倍数，不碰 UIScreen。
    NDInstallOne(@"EBAppLogDeviceHelper", NSSelectorFromString(@"screenScale"), YES,
                 'd', 0, "", (IMP)nd_hook_ebScreenScale, &nd_o_ebScreenScale);
    NDInstallOne(@"EBAppLogDeviceHelper", NSSelectorFromString(@"resolutionString"), YES,
                 '@', 0, "", (IMP)nd_hook_ebResolutionString, &nd_o_ebResolutionString);
    NDInstallEBResolution();
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
static SEL g_nduSelWkLoad = NULL;
static SEL g_nduSelPassLoad = NULL;
static SEL g_nduSelPassInitWK = NULL;
static SEL g_nduSelSapiLoadCk = NULL;
static SEL g_nduSelWkDefaultUA = NULL;
static SEL g_nduSelSetHdr = NULL;
static SEL g_nduSelDt1 = NULL;
static SEL g_nduSelDt2 = NULL;
static SEL g_nduSelConn = NULL;
static SEL g_nduSelUdSet = NULL;

// 1) -[WKWebView setCustomUserAgent:]：改写入参再下发
static void ndu_tr_wkSetUA(id self, SEL _cmd, id ua) {
    id out = ua;
    NDConfig *c = NDCurrentConfig();
    if (c.enabled && c.spoofUA && [ua isKindOfClass:NSString.class] && NDUAContainsReal(ua, c))
        out = NDRewriteUA(ua, c);
    ((void(*)(id, SEL, id))objc_msgSend)(self, g_nduSelWkSetUA, out);
    if (c && c.enabled && c.spoofBaiduSDK)
        NDSyncDVIFToStore(NDCookieStoreFromWebView(self), nil);
}

// 1b) -[WKWebView loadRequest:]：登录页导航前把 DVIF 写入该 WebView 的 WKHTTPCookieStore
static id ndu_tr_wkLoad(id self, SEL _cmd, id req) {
    NSURLRequest *r = [req isKindOfClass:NSURLRequest.class] ? (NSURLRequest *)req : nil;
    NDConfig *c = NDCurrentConfig();
    if (!r || !c || !c.enabled || !c.spoofBaiduSDK || !NDURLNeedsDVIF(r.URL) || NDRequestHasDVIF(r)) {
        return ((id(*)(id, SEL, id))objc_msgSend)(self, g_nduSelWkLoad, req);
    }
    NDEnsureDeviceCookie();
    __block BOOL went = NO;
    __block id nav = nil;
    void (^go)(void) = ^{
        if (went) return;
        went = YES;
        NSURLRequest *out = NDRequestAppendingDVIFCookie(r);
        nav = ((id(*)(id, SEL, id))objc_msgSend)(self, g_nduSelWkLoad, out);
    };
    NDSyncDVIFToStore(NDCookieStoreFromWebView(self), go);
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.4 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), go);
    return nav;
}

// 1c) -[PASSWebView loadRequest:]：SAPI 登录页真正走这里，再转给内部 WKWebView
static id ndu_tr_passLoad(id self, SEL _cmd, id req) {
    NSURLRequest *r = [req isKindOfClass:NSURLRequest.class] ? (NSURLRequest *)req : nil;
    NDConfig *c = NDCurrentConfig();
    if (!r || !c || !c.enabled || !c.spoofBaiduSDK || !NDURLNeedsDVIF(r.URL)) {
        return ((id(*)(id, SEL, id))objc_msgSend)(self, g_nduSelPassLoad, req);
    }
    NDEnsureDeviceCookie();
    id wv = NDRealWebView(self);
    __block BOOL went = NO;
    __block id nav = nil;
    void (^go)(void) = ^{
        if (went) return;
        went = YES;
        NSURLRequest *out = NDRequestAppendingDVIFCookie(r);
        nav = ((id(*)(id, SEL, id))objc_msgSend)(self, g_nduSelPassLoad, out);
    };
    NDSyncDVIFToStore(NDCookieStoreFromWebView(wv ?: self), go);
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.4 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), go);
    return nav;
}

static void ndu_tr_passInitWK(id self, SEL _cmd) {
    ((void(*)(id, SEL))objc_msgSend)(self, g_nduSelPassInitWK);
    NDConfig *c = NDCurrentConfig();
    if (!c || !c.enabled || !c.spoofBaiduSDK) return;
    NDEnsureDeviceCookie();
    NDSyncDVIFToStore(NDCookieStoreFromWebView(NDRealWebView(self)), nil);
}

static void ndu_tr_sapiLoadCk(id self, SEL _cmd, id url, id cookies) {
    NDConfig *c = NDCurrentConfig();
    id outCk = cookies;
    if (c && c.enabled && c.spoofBaiduSDK) {
        NDEnsureDeviceCookie();
        NSArray *dv = NDDVIFCookiesFromShared();
        if (dv.count) {
            NSMutableArray *m = [NSMutableArray array];
            if ([cookies isKindOfClass:NSArray.class]) [m addObjectsFromArray:cookies];
            [m addObjectsFromArray:dv];
            outCk = m;
        }
    }
    ((void(*)(id, SEL, id, id))objc_msgSend)(self, g_nduSelSapiLoadCk, url, outCk);
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

// 5) NSUserDefaults setObject:forKey: 出口：NADSplash / sofire / UA 缓存键收口；非目标 key 立即透传。
static void ndu_tr_udSet(id self, SEL _cmd, id value, id key) {
    id out = value;
    NDConfig *c = NDCurrentConfig();
    if (g_nduInRewrite == 0 && c.enabled && c.spoofBaiduSDK &&
        [key isKindOfClass:NSString.class]) {
        @try {
            id rewritten = NDRewriteDefaultsValue((NSString *)key, value, c);
            if (rewritten != value) out = rewritten;
        } @catch (__unused NSException *e) {}
    }
    ((void(*)(id, SEL, id, id))objc_msgSend)(self, g_nduSelUdSet, out, key);
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
            Method ml = NDUOwnMethod(wk, @selector(loadRequest:));
            if (ml) NDUSwap(wk, @selector(loadRequest:), (IMP)ndu_tr_wkLoad,
                            g_nduSelWkLoad, method_getTypeEncoding(ml));
        }
        Class pass = NSClassFromString(@"PASSWebView");
        if (pass) {
            Method m = NDUOwnMethod(pass, @selector(loadRequest:));
            if (m) NDUSwap(pass, @selector(loadRequest:), (IMP)ndu_tr_passLoad,
                           g_nduSelPassLoad, method_getTypeEncoding(m));
            SEL initWK = NSSelectorFromString(@"initWKWebView");
            Method mi = NDUOwnMethod(pass, initWK);
            if (mi) NDUSwap(pass, initWK, (IMP)ndu_tr_passInitWK,
                            g_nduSelPassInitWK, method_getTypeEncoding(mi));
        }
        Class swv = NSClassFromString(@"SAPIWebView");
        if (swv) {
            SEL loadCk = NSSelectorFromString(@"load:cookies:");
            Method mc = NDUOwnMethod(swv, loadCk);
            if (mc) NDUSwap(swv, loadCk, (IMP)ndu_tr_sapiLoadCk,
                            g_nduSelSapiLoadCk, method_getTypeEncoding(mc));
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
        // 5. NSUserDefaults 类簇：基类 + 覆盖了 setObject:forKey: 的子类（NADSplash/sofire/UA 缓存出口）
        Class udBase = NSClassFromString(@"NSUserDefaults");
        if (udBase) {
            Method m0 = NDUOwnMethod(udBase, @selector(setObject:forKey:));
            if (m0) NDUSwap(udBase, @selector(setObject:forKey:), (IMP)ndu_tr_udSet,
                            g_nduSelUdSet, method_getTypeEncoding(m0));
            unsigned int ucn = 0;
            Class *uclasses = objc_copyClassList(&ucn);
            if (uclasses) {
                for (unsigned int i = 0; i < ucn; i++) {
                    Class uc = uclasses[i];
                    if (uc == udBase || !NDUIsSubclassOrSame(uc, udBase)) continue;
                    Method mm = NDUOwnMethod(uc, @selector(setObject:forKey:));
                    if (mm) NDUSwap(uc, @selector(setObject:forKey:), (IMP)ndu_tr_udSet,
                                    g_nduSelUdSet, method_getTypeEncoding(mm));
                }
                free(uclasses);
            }
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
        g_nduSelWkLoad = sel_registerName("ndu_orig_wkLoad:");
        g_nduSelPassLoad = sel_registerName("ndu_orig_passLoad:");
        g_nduSelPassInitWK = sel_registerName("ndu_orig_passInitWK");
        g_nduSelSapiLoadCk = sel_registerName("ndu_orig_sapiLoadCk::");
        g_nduSelWkDefaultUA = sel_registerName("ndu_orig_wkDefaultUA");
        g_nduSelSetHdr = sel_registerName("ndu_orig_setHdr::");
        g_nduSelDt1 = sel_registerName("ndu_orig_dt1:");
        g_nduSelDt2 = sel_registerName("ndu_orig_dt2::");
        g_nduSelConn = sel_registerName("ndu_orig_conn:::");
        g_nduSelUdSet = sel_registerName("ndu_orig_udSet::");
        NDUScanPass();
    });
}

// NSUserDefaults 出口必须在 constructor 同步安装：NADSplash/sofire/UA 缓存均在 App 启动早期
// （主队列 block 之前）经 setObject:forKey: 写入，装晚了会错过首次写入，让真机值落盘。
// 基类 + 当前已加载且自身实现 setObject 的子类；晚加载子类由主队列 NDUScanPass 重试补齐（幂等）。
static void NDEarlyInstallDefaults(void) {
    Class udBase = NSClassFromString(@"NSUserDefaults");
    if (!udBase) return;
    if (!g_nduSelUdSet) g_nduSelUdSet = sel_registerName("ndu_orig_udSet::");
    Method m0 = NDUOwnMethod(udBase, @selector(setObject:forKey:));
    if (m0) NDUSwap(udBase, @selector(setObject:forKey:), (IMP)ndu_tr_udSet,
                    g_nduSelUdSet, method_getTypeEncoding(m0));
    unsigned int ucn = 0;
    Class *uclasses = objc_copyClassList(&ucn);
    if (uclasses) {
        for (unsigned int i = 0; i < ucn; i++) {
            Class uc = uclasses[i];
            if (uc == udBase || !NDUIsSubclassOrSame(uc, udBase)) continue;
            Method mm = NDUOwnMethod(uc, @selector(setObject:forKey:));
            if (mm) NDUSwap(uc, @selector(setObject:forKey:), (IMP)ndu_tr_udSet,
                            g_nduSelUdSet, method_getTypeEncoding(mm));
        }
        free(uclasses);
    }
}

// 启动期 hook 全部在 constructor 同步安装，抢在 App 网络库构造 NADSplash/sofire/UA 缓存之前：
// NDInstallAll 覆盖 UIDevice/NSProcessInfo/SAPI/BDPUserAgent，NDEarlyInstallDefaults 覆盖
// NSUserDefaults 出口；主队列 NDStartObjCHooks 仍做 dyld 回调与重试兜底，安装均幂等。
static void NDEarlyInstall(void) {
    NDInstallAll();
    NDEarlyInstallDefaults();
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

@interface NDFloatWindow : UIWindow
@end
@implementation NDFloatWindow
- (BOOL)canBecomeKeyWindow {
    return self.rootViewController.presentedViewController != nil;
}
- (UIView *)hitTest:(CGPoint)point withEvent:(UIEvent *)event {
    UIView *hit = [super hitTest:point withEvent:event];
    if (hit == self || hit == self.rootViewController.view) return nil;
    return hit;
}
@end

static UIButton *g_floatBtn = nil;
static UIWindow *g_floatWin = nil;
static BOOL g_floatDocked = NO;
static BOOL g_floatDockTimerOn = NO;
static BOOL g_floatLoginOK = NO;
static uint32_t g_floatDockGen = 0;

static void NDShowReport(void);

static BOOL NDVCHasLogin(UIViewController *vc) {
    if (!vc) return NO;
    NSString *n = NSStringFromClass(vc.class);
    if ([n containsString:@"PASSWebViewController"] || [n containsString:@"SAPIWebView"])
        return YES;
    if (NDVCHasLogin(vc.presentedViewController)) return YES;
    if ([vc isKindOfClass:UINavigationController.class])
        return NDVCHasLogin(((UINavigationController *)vc).visibleViewController);
    if ([vc isKindOfClass:UITabBarController.class])
        return NDVCHasLogin(((UITabBarController *)vc).selectedViewController);
    for (UIViewController *c in vc.childViewControllers) {
        if (NDVCHasLogin(c)) return YES;
    }
    return NO;
}

static BOOL NDLoginUIVisible(void) {
    UIViewController *root = nil;
    for (UIScene *scene in UIApplication.sharedApplication.connectedScenes) {
        if (![scene isKindOfClass:UIWindowScene.class]) continue;
        if (scene.activationState != UISceneActivationStateForegroundActive) continue;
        for (UIWindow *win in ((UIWindowScene *)scene).windows) {
            if (win.isKeyWindow) { root = win.rootViewController; break; }
        }
    }
    if (!root) root = UIApplication.sharedApplication.keyWindow.rootViewController;
    return NDVCHasLogin(root);
}

static void NDFloatApplyDock(BOOL docked, BOOL animated) {
    if (!g_floatBtn) return;
    g_floatDocked = docked;
    CGRect r = g_floatBtn.frame;
    CGFloat peek = 16.0;
    r.origin.x = docked ? (peek - r.size.width) : 8.0;
    void (^go)(void) = ^{ g_floatBtn.frame = r; };
    if (animated) {
        [UIView animateWithDuration:0.28 delay:0
                            options:UIViewAnimationOptionCurveEaseInOut
                         animations:go completion:nil];
    } else {
        go();
    }
}

static void NDFloatScheduleDock(void) {
    if (!g_floatBtn || g_floatDocked || g_floatDockTimerOn) return;
    if (!g_floatLoginOK) return;
    g_floatDockTimerOn = YES;
    uint32_t gen = ++g_floatDockGen;
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(15.0 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        g_floatDockTimerOn = NO;
        if (gen != g_floatDockGen) return;
        if (!g_floatBtn || !g_floatLoginOK) return;
        NDFloatApplyDock(YES, YES);
    });
}

static void NDFloatOnLoginSuccess(void) {
    dispatch_async(dispatch_get_main_queue(), ^{
        g_floatLoginOK = YES;
        NDFloatScheduleDock();
    });
}

static void NDFloatOnLogout(void) {
    dispatch_async(dispatch_get_main_queue(), ^{
        g_floatLoginOK = NO;
        g_floatDockGen++;
        g_floatDockTimerOn = NO;
        NDFloatApplyDock(NO, YES);
    });
}

static void NDFloatTapped(void) {
    g_floatDockGen++;
    g_floatDockTimerOn = NO;
    if (g_floatDocked) NDFloatApplyDock(NO, YES);
    NDShowReport();
    if (g_floatLoginOK) NDFloatScheduleDock();
}

static void NDFloatMaybeAlreadyLoggedIn(void) {
    if (g_floatLoginOK) {
        NDFloatScheduleDock();
        return;
    }
    if (NDLoginUIVisible()) return;
    Class cm = NSClassFromString(@"SAPICookieManager");
    SEL s = NSSelectorFromString(@"getBdussFromCookie");
    if (!(cm && [cm respondsToSelector:s])) return;
    id v = ((id (*)(id, SEL))objc_msgSend)(cm, s);
    if (![v isKindOfClass:NSString.class] || ((NSString *)v).length < 8) return;
    g_floatLoginOK = YES;
    NDFloatScheduleDock();
}

static UIViewController *NDTopVC(void) {
    UIViewController *vc = UIApplication.sharedApplication.keyWindow.rootViewController;
    while (vc.presentedViewController) vc = vc.presentedViewController;
    while ([vc isKindOfClass:UINavigationController.class]) {
        vc = ((UINavigationController *)vc).visibleViewController;
    }
    return vc;
}

static UIViewController *NDFloatHostVC(void) {
    UIViewController *vc = g_floatWin.rootViewController;
    if (vc) return vc;
    return NDTopVC();
}

static NSString *NDShortUA(NSString *ua) {
    if (![ua isKindOfClass:NSString.class] || !ua.length) return @"(未写入)";
    NSRegularExpression *rx = [NSRegularExpression regularExpressionWithPattern:
        @"CPU iPhone OS [0-9_]+|Baidu; P2 [0-9.]+|_[0-9]+\.[0-9]+(?:\.[0-9]+)?"
                                                                       options:0 error:nil];
    NSTextCheckingResult *m = [rx firstMatchInString:ua options:0 range:NSMakeRange(0, ua.length)];
    if (m) return [ua substringWithRange:m.range];
    return ua.length > 48 ? [[ua substringToIndex:48] stringByAppendingString:@"…"] : ua;
}

// ============================== 自检报告卡片（屏幕内可滚动查看 / 复制 / 转发） ==============================
@interface NDReportVC : UIViewController <UIGestureRecognizerDelegate>
@property(nonatomic, copy) NSString *report;
- (instancetype)initWithReport:(NSString *)report;
- (void)ndCopy;
- (void)ndShare;
- (void)ndClose;
@end

@implementation NDReportVC {
    UITextView *_textView;
    UIButton *_copyBtn;
}

- (instancetype)initWithReport:(NSString *)report {
    self = [super initWithNibName:nil bundle:nil];
    if (self) {
        _report = [report copy];
        self.modalPresentationStyle = UIModalPresentationOverFullScreen;
        self.modalTransitionStyle = UIModalTransitionStyleCrossDissolve;
    }
    return self;
}

- (UIButton *)ndButtonWithTitle:(NSString *)title action:(SEL)action {
    UIButton *b = [UIButton buttonWithType:UIButtonTypeSystem];
    [b setTitle:title forState:UIControlStateNormal];
    [b setTitleColor:UIColor.whiteColor forState:UIControlStateNormal];
    b.titleLabel.font = [UIFont boldSystemFontOfSize:15];
    b.layer.cornerRadius = 10;
    b.layer.masksToBounds = YES;
    b.translatesAutoresizingMaskIntoConstraints = NO;
    [b addTarget:self action:action forControlEvents:UIControlEventTouchUpInside];
    return b;
}

- (void)viewDidLoad {
    [super viewDidLoad];
    self.view.backgroundColor = [UIColor colorWithWhite:0 alpha:0.55];

    UITapGestureRecognizer *bgTap = [[UITapGestureRecognizer alloc] initWithTarget:self
                                                                            action:@selector(ndClose)];
    bgTap.delegate = self;
    [self.view addGestureRecognizer:bgTap];

    UIView *card = [UIView new];
    card.backgroundColor = [UIColor colorWithRed:0.12 green:0.13 blue:0.15 alpha:1.0];
    card.layer.cornerRadius = 16;
    card.layer.masksToBounds = YES;
    card.translatesAutoresizingMaskIntoConstraints = NO;
    [self.view addSubview:card];

    UILabel *titleLbl = [UILabel new];
    titleLbl.text = @"网解 · 自检报告";
    titleLbl.textColor = UIColor.whiteColor;
    titleLbl.font = [UIFont boldSystemFontOfSize:16];
    titleLbl.translatesAutoresizingMaskIntoConstraints = NO;
    [card addSubview:titleLbl];

    UIButton *closeX = [UIButton buttonWithType:UIButtonTypeSystem];
    [closeX setTitle:@"✕" forState:UIControlStateNormal];
    [closeX setTitleColor:UIColor.lightGrayColor forState:UIControlStateNormal];
    closeX.titleLabel.font = [UIFont boldSystemFontOfSize:18];
    closeX.translatesAutoresizingMaskIntoConstraints = NO;
    [closeX addTarget:self action:@selector(ndClose) forControlEvents:UIControlEventTouchUpInside];
    [card addSubview:closeX];

    _textView = [[UITextView alloc] init];
    _textView.text = self.report;
    _textView.editable = NO;
    _textView.selectable = YES;
    _textView.backgroundColor = UIColor.clearColor;
    _textView.textColor = [UIColor colorWithRed:0.92 green:0.94 blue:0.96 alpha:1.0];
    UIFont *mono = [UIFont fontWithName:@"Menlo" size:11];
    _textView.font = mono ?: [UIFont systemFontOfSize:11];
    _textView.alwaysBounceVertical = YES;
    _textView.showsVerticalScrollIndicator = YES;
    _textView.translatesAutoresizingMaskIntoConstraints = NO;
    [card addSubview:_textView];

    _copyBtn = [self ndButtonWithTitle:@"复制" action:@selector(ndCopy)];
    UIButton *shareBtn = [self ndButtonWithTitle:@"转发" action:@selector(ndShare)];
    UIButton *closeBtn = [self ndButtonWithTitle:@"关闭" action:@selector(ndClose)];
    _copyBtn.backgroundColor = [UIColor colorWithRed:0.22 green:0.24 blue:0.28 alpha:1.0];
    shareBtn.backgroundColor = [UIColor colorWithRed:0.10 green:0.55 blue:0.95 alpha:1.0];
    closeBtn.backgroundColor = [UIColor colorWithRed:0.22 green:0.24 blue:0.28 alpha:1.0];
    [card addSubview:_copyBtn];
    [card addSubview:shareBtn];
    [card addSubview:closeBtn];

    UILayoutGuide *safe = self.view.safeAreaLayoutGuide;
    [NSLayoutConstraint activateConstraints:@[
        [card.centerXAnchor constraintEqualToAnchor:safe.centerXAnchor],
        [card.centerYAnchor constraintEqualToAnchor:safe.centerYAnchor],
        [card.widthAnchor constraintEqualToAnchor:safe.widthAnchor multiplier:0.92],
        [card.heightAnchor constraintEqualToAnchor:safe.heightAnchor multiplier:0.80],

        [titleLbl.topAnchor constraintEqualToAnchor:card.topAnchor constant:14],
        [titleLbl.leadingAnchor constraintEqualToAnchor:card.leadingAnchor constant:16],

        [closeX.centerYAnchor constraintEqualToAnchor:titleLbl.centerYAnchor],
        [closeX.trailingAnchor constraintEqualToAnchor:card.trailingAnchor constant:-14],
        [closeX.widthAnchor constraintEqualToConstant:30],

        [_textView.topAnchor constraintEqualToAnchor:titleLbl.bottomAnchor constant:10],
        [_textView.leadingAnchor constraintEqualToAnchor:card.leadingAnchor constant:14],
        [_textView.trailingAnchor constraintEqualToAnchor:card.trailingAnchor constant:-14],
        [_textView.bottomAnchor constraintEqualToAnchor:_copyBtn.topAnchor constant:-12],

        [closeBtn.bottomAnchor constraintEqualToAnchor:card.bottomAnchor constant:-14],
        [closeBtn.trailingAnchor constraintEqualToAnchor:card.trailingAnchor constant:-14],
        [closeBtn.widthAnchor constraintEqualToConstant:80],
        [closeBtn.heightAnchor constraintEqualToConstant:40],

        [shareBtn.bottomAnchor constraintEqualToAnchor:card.bottomAnchor constant:-14],
        [shareBtn.trailingAnchor constraintEqualToAnchor:closeBtn.leadingAnchor constant:-10],
        [shareBtn.widthAnchor constraintEqualToConstant:80],
        [shareBtn.heightAnchor constraintEqualToConstant:40],

        [_copyBtn.bottomAnchor constraintEqualToAnchor:card.bottomAnchor constant:-14],
        [_copyBtn.trailingAnchor constraintEqualToAnchor:shareBtn.leadingAnchor constant:-10],
        [_copyBtn.widthAnchor constraintEqualToConstant:80],
        [_copyBtn.heightAnchor constraintEqualToConstant:40],
    ]];
}

// 仅当触摸落在遮罩本身时才响应关闭，点卡片内部不关闭
- (BOOL)gestureRecognizer:(UIGestureRecognizer *)gestureRecognizer shouldReceiveTouch:(UITouch *)touch {
    return touch.view == self.view;
}

- (void)ndClose {
    [self dismissViewControllerAnimated:YES completion:nil];
}

- (void)ndCopy {
    [UIPasteboard generalPasteboard].string = self.report ?: @"";
    [_copyBtn setTitle:@"已复制" forState:UIControlStateNormal];
    __weak UIButton *weakBtn = _copyBtn;
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.2 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        [weakBtn setTitle:@"复制" forState:UIControlStateNormal];
    });
}

- (void)ndShare {
    NSString *r = self.report;
    [self dismissViewControllerAnimated:NO completion:^{
        UIActivityViewController *ac = [[UIActivityViewController alloc]
            initWithActivityItems:@[r ?: @""] applicationActivities:nil];
        UIViewController *top = NDFloatHostVC();
        if (top) [top presentViewController:ac animated:YES completion:nil];
    }];
}

@end

static void NDShowReport(void) {
    NDConfig *c = NDCurrentConfig();
    NSMutableString *r = [NSMutableString string];
    [r appendFormat:@"NDSpoofer 9.21-06\n\n"];
    [r appendFormat:@"总开关：%@\n", c.enabled ? @"开" : @"关"];
    [r appendFormat:@"C层(sysctl/uname)：%@\nUIDevice：%@\n百度SDK：%@\nUA：%@\nIDFV：%@\n磁盘：%@\n屏幕：%@\nPASS_CUSTOM：%@\n",
        c.spoofSysctl ? @"开" : @"关", c.spoofUIDevice ? @"开" : @"关", c.spoofBaiduSDK ? @"开" : @"关",
        c.spoofUA ? @"开" : @"关", c.spoofIDFV ? @"开" : @"关", c.spoofStorage ? @"开" : @"关",
        c.spoofScreen ? @"开" : @"关", c.seedPassCustom ? @"开" : @"关"];
    [r appendFormat:@"\n伪装机型：%@ (%@)\n营销名：%@\n伪装系统：%@ (%@)\n内存：%ldMB\n磁盘：%ldGB\n配置屏幕：%.0fx%.0f @%.0fx / 物理%.0fx%.0f\n",
        c.hwMachine, c.hwModel, c.marketingName, c.systemVersion, c.systemBuild,
        (long)c.memorySizeMB, (long)c.diskSizeGB,
        c.screenWidth, c.screenHeight, c.screenScale,
        c.nativeScreenWidth, c.nativeScreenHeight];
    [r appendFormat:@"\n真机机型：%@ (%@)\n真机系统：%@ (%@)\n真机内存：%lluMB\n真机磁盘：%lluGB\n",
        c.realMachine, c.realModel, c.realOSVersion, c.realBuild,
        c.realMemBytes / 1024 / 1024, c.realDiskBytes / 1024 / 1024 / 1024];
    [r appendFormat:@"\n已安装 Hook：%d 个\n", g_installed];
    NSUserDefaults *d = [NSUserDefaults standardUserDefaults];
    [r appendFormat:@"\nPASS_CUSTOM_SYS_VER：%@\n", [d stringForKey:@"PASS_CUSTOM_SYS_VER"] ?: @"(未设置)"];
    [r appendFormat:@"PASS_CUSTOM_UA_WK：%@\n", [d stringForKey:@"PASS_CUSTOM_UA_WK"] ?: @"(未设置)"];

    // 9.20-05 通道自检：直接调用会经过 NSProcessInfo hook；读 NSUserDefaults 看到的是出口收口后的实际值。
    [r appendString:@"\n—— 9.20-05 通道自检 ——\n"];
    NSProcessInfo *pi = [NSProcessInfo processInfo];
    [r appendFormat:@"NSProcessInfo 内存：%lluMB\n", pi.physicalMemory / 1024ULL / 1024ULL];
    [r appendFormat:@"NSProcessInfo 系统：%@\n", pi.operatingSystemVersionString];
    NSOperatingSystemVersion osv = pi.operatingSystemVersion;
    [r appendFormat:@"NSProcessInfo 版本：%ld.%ld.%ld\n",
        (long)osv.majorVersion, (long)osv.minorVersion, (long)osv.patchVersion];
    id splash = [d objectForKey:@"NADSplashLatestLogFormationKeyName"];
    if ([splash isKindOfClass:NSDictionary.class]) {
        NSDictionary *sd = (NSDictionary *)splash;
        [r appendFormat:@"NADSplash 系统/内存：%@ / %@\n", sd[@"systemVersion"] ?: @"-", sd[@"physicalMemory"] ?: @"-"];
    } else {
        [r appendString:@"NADSplash：(尚未写入)\n"];
    }
    id sofire = [d objectForKey:@"dvlwfrqupdt"];
    if ([sofire isKindOfClass:NSDictionary.class]) {
        [r appendFormat:@"sofire hwphysm：%@\n", ((NSDictionary *)sofire)[@"hwphysm"] ?: @"-"];
    } else {
        [r appendString:@"sofire：(尚未写入)\n"];
    }
    [r appendFormat:@"NAD UA：%@\n", NDShortUA([d stringForKey:@"NADUserAgentKey"])];
    [r appendFormat:@"BBA Check：%@\n", [d stringForKey:@"BBAUserAgentCheckInfoKey"] ?: @"(未写入)"];

    // 9.21-01 屏幕通道自检：直接调用百度统计类方法会经过 hook，显示上报层实际值（非 UIScreen）。
    Class ebCls = NSClassFromString(@"EBAppLogDeviceHelper");
    if (ebCls) {
        [r appendString:@"\n—— 9.21-01 屏幕上报自检（EBAppLog）——\n"];
        SEL sRes = NSSelectorFromString(@"resolution");
        SEL sScale = NSSelectorFromString(@"screenScale");
        SEL sStr = NSSelectorFromString(@"resolutionString");
        if ([ebCls respondsToSelector:sRes]) {
            CGSize ebR = ((CGSize (*)(id, SEL))[ebCls methodForSelector:sRes])(ebCls, sRes);
            [r appendFormat:@"统计上报分辨率：%.0fx%.0f（逻辑×scale）\n", ebR.width, ebR.height];
        }
        if ([ebCls respondsToSelector:sScale]) {
            double ebS = ((double (*)(id, SEL))[ebCls methodForSelector:sScale])(ebCls, sScale);
            [r appendFormat:@"统计缩放倍数：%.2f\n", ebS];
        }
        if ([ebCls respondsToSelector:sStr]) {
            NSString *ebStr = ((NSString *(*)(id, SEL))[ebCls methodForSelector:sStr])(ebCls, sStr);
            [r appendFormat:@"统计分辨率串：%@\n", ebStr ?: @"-"];
        }
    } else {
        [r appendString:@"\nEBAppLogDeviceHelper：(类未加载，进 App 后再看)\n"];
    }

    NDReportVC *rc = [[NDReportVC alloc] initWithReport:r];
    UIViewController *host = NDFloatHostVC();
    if (host) [host presentViewController:rc animated:YES completion:nil];
}

static UIWindowScene *NDActiveWindowScene(void) {
    UIWindowScene *fallback = nil;
    for (UIScene *s in UIApplication.sharedApplication.connectedScenes) {
        if (![s isKindOfClass:UIWindowScene.class]) continue;
        UIWindowScene *ws = (UIWindowScene *)s;
        if (ws.activationState == UISceneActivationStateForegroundActive) return ws;
        if (!fallback) fallback = ws;
    }
    return fallback;
}

static void NDEnsureFloatWindow(void) {
    if (![NSThread isMainThread]) {
        dispatch_async(dispatch_get_main_queue(), ^{ NDEnsureFloatWindow(); });
        return;
    }
    UIWindowScene *scene = NDActiveWindowScene();
    if (g_floatWin && g_floatBtn) {
        if (scene && g_floatWin.windowScene != scene) g_floatWin.windowScene = scene;
        g_floatWin.windowLevel = UIWindowLevelAlert + 1;
        g_floatWin.hidden = NO;
        return;
    }
    if (!scene) return;

    NDFloatWindow *win = [[NDFloatWindow alloc] initWithWindowScene:scene];
    win.frame = scene.coordinateSpace.bounds;
    win.windowLevel = UIWindowLevelAlert + 1;
    win.backgroundColor = UIColor.clearColor;
    win.opaque = NO;
    win.userInteractionEnabled = YES;

    UIViewController *root = [[UIViewController alloc] init];
    root.view.backgroundColor = UIColor.clearColor;
    win.rootViewController = root;

    UIButton *b = [UIButton buttonWithType:UIButtonTypeSystem];
    b.frame = CGRectMake(8, 120, 56, 56);
    b.layer.cornerRadius = 28;
    b.layer.masksToBounds = YES;
    b.backgroundColor = [UIColor colorWithRed:0.10 green:0.55 blue:0.95 alpha:0.85];
    b.titleLabel.font = [UIFont boldSystemFontOfSize:15];
    b.titleLabel.numberOfLines = 1;
    [b setTitle:@"网解" forState:UIControlStateNormal];
    [b setTitleColor:UIColor.whiteColor forState:UIControlStateNormal];
    [b addAction:[UIAction actionWithHandler:^(__unused UIAction *action) {
        NDFloatTapped();
    }] forControlEvents:UIControlEventTouchUpInside];
    b.autoresizingMask = UIViewAutoresizingFlexibleRightMargin | UIViewAutoresizingFlexibleBottomMargin;
    [root.view addSubview:b];

    g_floatWin = win;
    g_floatBtn = b;
    win.hidden = NO;
    NDFloatMaybeAlreadyLoggedIn();
}

static void NDSetupFloatButton(void) {
    dispatch_async(dispatch_get_main_queue(), ^{
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3.0 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            NDEnsureFloatWindow();
            if (g_floatBtn) return;
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0 * NSEC_PER_SEC)),
                           dispatch_get_main_queue(), ^{
                NDEnsureFloatWindow();
            });
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
        NDEarlyInstall();
        NDStartObjCHooks();
        NDSetupFloatButton();

        // 管理器在 App 冷启动前写配置；回到前台时再读一次，兼容换容器后重启场景。
        [[NSNotificationCenter defaultCenter] addObserverForName:UIApplicationWillEnterForegroundNotification
                                                          object:nil queue:NSOperationQueue.mainQueue
                                                      usingBlock:^(__unused NSNotification *note) {
            NDLoadConfig();
            NDEnsureFloatWindow();
        }];
        NSLog(@"[NDSpoofer] loaded profile=%@ (%@) iOS %@",
              c.hwMachine, c.hwModel, c.systemVersion);
    }
}
