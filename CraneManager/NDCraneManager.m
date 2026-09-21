//
//  NDCraneManager.m  —  网解（卍解）：为百度网盘的 Crane 容器逐容器写入 NDSpoofer 配置
//
//  版本：9.21-04
//
//  9.21-02：管理器与悬浮球名称统一改为“网解”。
//
//  用法：多选容器 → 一键随机网盘身份（每个容器一套独立机型/系统/IDFV）。
//  9.21-01：机型池扩到 36 套（iPhone 8 ~ iPhone 17 系列，含异屏机型），每套带真实
//  逻辑/物理分辨率与 scale；dylib 仅 hook 百度统计 EBAppLogDeviceHelper 的屏幕上报出口，
//  绝不触碰 UIScreen，页面布局仍用真机尺寸，不卡死、不影响触摸。
//

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <dlfcn.h>

static NSString * const NDTargetBundleID = @"com.baidu.netdisk";
static NSString * const NDConfigFileName = @"ndspoofer_config.plist";

typedef NS_ENUM(NSInteger, NDCraneContainerPathType) {
    NDCraneContainerPathTypeApp = 0,
    NDCraneContainerPathTypeGroup = 1,
    NDCraneContainerPathTypePlugin = 2,
};

@interface CraneManager : NSObject
+ (instancetype)sharedManager;
- (BOOL)isApplicationSupportedByCrane:(NSString *)applicationID;
- (NSArray *)containerIdentifiersOfApplicationWithIdentifier:(NSString *)applicationID;
- (NSString *)activeContainerIdentifierForApplicationWithIdentifier:(NSString *)applicationID;
- (NSString *)displayNameForContainerWithIdentifier:(NSString *)containerID
                             ofApplicationWithIdentifier:(NSString *)applicationID
                                   shouldUseShortVersion:(BOOL)shortVersion;
- (void)enumerate:(void (^)(NDCraneContainerPathType type, NSString *identifier, NSString *path))block
        pathsAssociatedToContainerWithIdentifier:(NSString *)containerID
                          ofApplicationWithIdentifier:(NSString *)applicationID;
- (NSDictionary *)pathsAssociatedToContainerWithIdentifier:(NSString *)containerID
                            ofApplicationWithIdentifier:(NSString *)applicationID;
@end

@interface LSApplicationProxy : NSObject
+ (instancetype)applicationProxyForIdentifier:(NSString *)applicationIdentifier;
@property(nonatomic, readonly) NSURL *dataContainerURL;
@end

// ============================== 机型 / 系统池 ==============================

static NSDictionary *NDDevice(NSString *name, NSString *machine, NSString *model,
                              NSString *marketing, NSString *cpuBrand,
                              NSInteger width, NSInteger height,
                              NSInteger nativeWidth, NSInteger nativeHeight,
                              NSInteger scale, NSInteger memory,
                              NSArray<NSNumber *> *disks,
                              NSString *minimumOS, NSInteger maximumMajor) {
    return @{
        @"name": name, @"machine": machine, @"model": model,
        @"marketing": marketing, @"cpuBrand": cpuBrand,
        // 屏幕参数随机型：width/height 为逻辑点，nativeWidth/Height 为物理像素，scale 为缩放倍数。
        // 仅用于管理器展示及 dylib 对百度统计上报值的改写；dylib 不 hook UIScreen。
        @"width": @(width), @"height": @(height),
        @"nativeWidth": @(nativeWidth), @"nativeHeight": @(nativeHeight), @"scale": @(scale),
        @"memory": @(memory), @"disks": disks,
        @"minimumOS": minimumOS, @"maximumMajor": @(maximumMajor)
    };
}

static NSArray<NSDictionary *> *NDDeviceProfiles(void) {
    static NSArray *profiles;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        profiles = @[
            NDDevice(@"iPhone 8", @"iPhone10,1", @"D20AP", @"iPhone8", @"Apple A11 Bionic",
                     375, 667, 750, 1334, 2, 2048, @[@64,@256], @"15.0", 16),
            NDDevice(@"iPhone 8 Plus", @"iPhone10,2", @"D21AP", @"iPhone8Plus", @"Apple A11 Bionic",
                     414, 736, 1080, 1920, 3, 3072, @[@64,@256], @"15.0", 16),
            NDDevice(@"iPhone X", @"iPhone10,3", @"D22AP", @"iPhoneX", @"Apple A11 Bionic",
                     375, 812, 1125, 2436, 3, 3072, @[@64,@256], @"15.0", 16),
            NDDevice(@"iPhone XR", @"iPhone11,8", @"N841AP", @"iPhoneXR", @"Apple A12 Bionic",
                     414, 896, 828, 1792, 2, 3072, @[@64,@128,@256], @"15.0", 18),
            NDDevice(@"iPhone XS", @"iPhone11,2", @"D321AP", @"iPhoneXS", @"Apple A12 Bionic",
                     375, 812, 1125, 2436, 3, 4096, @[@64,@256,@512], @"15.0", 18),
            NDDevice(@"iPhone XS Max", @"iPhone11,6", @"D331pAP", @"iPhoneXSMax", @"Apple A12 Bionic",
                     414, 896, 1242, 2688, 3, 4096, @[@64,@256,@512], @"15.0", 18),
            NDDevice(@"iPhone 11", @"iPhone12,1", @"N104AP", @"iPhone11", @"Apple A13 Bionic",
                     414, 896, 828, 1792, 2, 4096, @[@64,@128,@256], @"15.0", 26),
            NDDevice(@"iPhone 11 Pro", @"iPhone12,3", @"D421AP", @"iPhone11Pro", @"Apple A13 Bionic",
                     375, 812, 1125, 2436, 3, 4096, @[@64,@256,@512], @"15.0", 26),
            NDDevice(@"iPhone 11 Pro Max", @"iPhone12,5", @"D431AP", @"iPhone11ProMax", @"Apple A13 Bionic",
                     414, 896, 1242, 2688, 3, 4096, @[@64,@256,@512], @"15.0", 26),
            NDDevice(@"iPhone 12 mini", @"iPhone13,1", @"D52gAP", @"iPhone12mini", @"Apple A14 Bionic",
                     375, 812, 1080, 2340, 3, 4096, @[@64,@128,@256], @"15.0", 26),
            NDDevice(@"iPhone 12", @"iPhone13,2", @"D53gAP", @"iPhone12", @"Apple A14 Bionic",
                     390, 844, 1170, 2532, 3, 4096, @[@64,@128,@256], @"15.0", 26),
            NDDevice(@"iPhone 12 Pro", @"iPhone13,3", @"D53pAP", @"iPhone12Pro", @"Apple A14 Bionic",
                     390, 844, 1170, 2532, 3, 6144, @[@128,@256,@512], @"15.0", 26),
            NDDevice(@"iPhone 12 Pro Max", @"iPhone13,4", @"D54pAP", @"iPhone12ProMax", @"Apple A14 Bionic",
                     428, 926, 1284, 2778, 3, 6144, @[@128,@256,@512], @"15.0", 26),
            NDDevice(@"iPhone 13 mini", @"iPhone14,4", @"D16AP", @"iPhone13mini", @"Apple A15 Bionic",
                     375, 812, 1080, 2340, 3, 4096, @[@128,@256,@512], @"15.0", 26),
            NDDevice(@"iPhone 13", @"iPhone14,5", @"D17AP", @"iPhone13", @"Apple A15 Bionic",
                     390, 844, 1170, 2532, 3, 4096, @[@128,@256,@512], @"15.0", 26),
            NDDevice(@"iPhone 13 Pro", @"iPhone14,2", @"D63AP", @"iPhone13Pro", @"Apple A15 Bionic",
                     390, 844, 1170, 2532, 3, 6144, @[@128,@256,@512,@1024], @"15.0", 26),
            NDDevice(@"iPhone 13 Pro Max", @"iPhone14,3", @"D64AP", @"iPhone13ProMax", @"Apple A15 Bionic",
                     428, 926, 1284, 2778, 3, 6144, @[@128,@256,@512,@1024], @"15.0", 26),
            NDDevice(@"iPhone SE (3rd generation)", @"iPhone14,6", @"D49AP", @"iPhoneSE3", @"Apple A15 Bionic",
                     375, 667, 750, 1334, 2, 4096, @[@64,@128,@256], @"15.4", 26),
            NDDevice(@"iPhone 14", @"iPhone14,7", @"D27AP", @"iPhone14", @"Apple A15 Bionic",
                     390, 844, 1170, 2532, 3, 6144, @[@128,@256,@512], @"16.0", 26),
            NDDevice(@"iPhone 14 Pro", @"iPhone15,2", @"D73AP", @"iPhone14Pro", @"Apple A16 Bionic",
                     393, 852, 1179, 2556, 3, 6144, @[@128,@256,@512,@1024], @"16.0", 26),
            NDDevice(@"iPhone 14 Pro Max", @"iPhone15,3", @"D74AP", @"iPhone14ProMax", @"Apple A16 Bionic",
                     430, 932, 1290, 2796, 3, 6144, @[@128,@256,@512,@1024], @"16.0", 26),
            NDDevice(@"iPhone 14 Plus", @"iPhone14,8", @"D28AP", @"iPhone14Plus", @"Apple A15 Bionic",
                     428, 926, 1284, 2778, 3, 6144, @[@128,@256,@512], @"16.0.2", 26),
            NDDevice(@"iPhone 15", @"iPhone15,4", @"D37AP", @"iPhone15", @"Apple A16 Bionic",
                     393, 852, 1179, 2556, 3, 6144, @[@128,@256,@512], @"17.0", 26),
            NDDevice(@"iPhone 15 Plus", @"iPhone15,5", @"D38AP", @"iPhone15Plus", @"Apple A16 Bionic",
                     430, 932, 1290, 2796, 3, 6144, @[@128,@256,@512], @"17.0", 26),
            NDDevice(@"iPhone 15 Pro", @"iPhone16,1", @"D83AP", @"iPhone15Pro", @"Apple A17 Pro",
                     393, 852, 1179, 2556, 3, 8192, @[@128,@256,@512,@1024], @"17.0", 26),
            NDDevice(@"iPhone 15 Pro Max", @"iPhone16,2", @"D84AP", @"iPhone15ProMax", @"Apple A17 Pro",
                     430, 932, 1290, 2796, 3, 8192, @[@256,@512,@1024], @"17.0", 26),
            NDDevice(@"iPhone 16", @"iPhone17,3", @"D47AP", @"iPhone16", @"Apple A18",
                     393, 852, 1179, 2556, 3, 8192, @[@128,@256,@512], @"18.0", 26),
            NDDevice(@"iPhone 16 Plus", @"iPhone17,4", @"D48AP", @"iPhone16Plus", @"Apple A18",
                     430, 932, 1290, 2796, 3, 8192, @[@128,@256,@512], @"18.0", 26),
            NDDevice(@"iPhone 16 Pro", @"iPhone17,1", @"D93AP", @"iPhone16Pro", @"Apple A18 Pro",
                     402, 874, 1206, 2622, 3, 8192, @[@128,@256,@512,@1024], @"18.0", 26),
            NDDevice(@"iPhone 16 Pro Max", @"iPhone17,2", @"D94AP", @"iPhone16ProMax", @"Apple A18 Pro",
                     440, 956, 1320, 2868, 3, 8192, @[@256,@512,@1024], @"18.0", 26),
            NDDevice(@"iPhone 16e", @"iPhone17,5", @"V59AP", @"iPhone16e", @"Apple A18",
                     390, 844, 1170, 2532, 3, 8192, @[@128,@256,@512], @"18.3.1", 26),
            NDDevice(@"iPhone 17", @"iPhone18,3", @"V57AP", @"iPhone17", @"Apple A19",
                     402, 874, 1206, 2622, 3, 8192, @[@256,@512], @"26.0", 26),
            NDDevice(@"iPhone 17 Pro", @"iPhone18,1", @"V53AP", @"iPhone17Pro", @"Apple A19 Pro",
                     402, 874, 1206, 2622, 3, 12288, @[@256,@512,@1024], @"26.0", 26),
            NDDevice(@"iPhone 17 Pro Max", @"iPhone18,2", @"V54AP", @"iPhone17ProMax", @"Apple A19 Pro",
                     440, 956, 1320, 2868, 3, 12288, @[@256,@512,@1024], @"26.0", 26),
            NDDevice(@"iPhone Air", @"iPhone18,4", @"D23AP", @"iPhoneAir", @"Apple A19 Pro",
                     420, 912, 1260, 2736, 3, 12288, @[@256,@512,@1024], @"26.0", 26),
            NDDevice(@"iPhone 17e", @"iPhone18,5", @"V159AP", @"iPhone17e", @"Apple A19",
                     390, 844, 1170, 2532, 3, 8192, @[@128,@256,@512], @"26.3.1", 26),
        ];
    });
    return profiles;
}

static NSDictionary *NDSystem(NSString *version, NSString *build) {
    return @{@"version": version, @"build": build};
}

static NSArray<NSDictionary *> *NDSystemProfiles(void) {
    static NSArray *profiles;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        profiles = @[
            NDSystem(@"15.0", @"19A346"), NDSystem(@"15.0.2", @"19A404"),
            NDSystem(@"15.1.1", @"19B81"), NDSystem(@"15.2.1", @"19C63"),
            NDSystem(@"15.3", @"19D50"), NDSystem(@"15.3.1", @"19D52"),
            NDSystem(@"15.4", @"19E241"), NDSystem(@"15.4.1", @"19E258"),
            NDSystem(@"15.5", @"19F77"), NDSystem(@"15.6", @"19G71"),
            NDSystem(@"15.6.1", @"19G82"), NDSystem(@"15.7", @"19H12"),
            NDSystem(@"15.7.1", @"19H117"),
            NDSystem(@"16.0", @"20A362"), NDSystem(@"16.0.2", @"20A380"),
            NDSystem(@"16.0.3", @"20A392"), NDSystem(@"16.1", @"20B82"),
            NDSystem(@"16.1.1", @"20B101"), NDSystem(@"16.1.2", @"20B110"),
            NDSystem(@"16.2", @"20C65"), NDSystem(@"16.3", @"20D47"),
            NDSystem(@"16.3.1", @"20D67"), NDSystem(@"16.4", @"20E247"),
            NDSystem(@"16.4.1", @"20E252"), NDSystem(@"16.5", @"20F66"),
            NDSystem(@"16.5.1", @"20F75"), NDSystem(@"16.6", @"20G75"),
            NDSystem(@"16.6.1", @"20G81"), NDSystem(@"16.7", @"20H19"),
            NDSystem(@"16.7.1", @"20H30"), NDSystem(@"16.7.2", @"20H115"),
            NDSystem(@"16.7.15", @"20H380"), NDSystem(@"16.7.16", @"20H392"),
            NDSystem(@"17.0", @"21A329"), NDSystem(@"17.0.1", @"21A340"),
            NDSystem(@"17.0.2", @"21A351"), NDSystem(@"17.0.3", @"21A360"),
            NDSystem(@"17.1", @"21B74"), NDSystem(@"17.1.1", @"21B91"),
            NDSystem(@"17.1.2", @"21B101"), NDSystem(@"17.2", @"21C62"),
            NDSystem(@"17.2.1", @"21C66"), NDSystem(@"17.3", @"21D50"),
            NDSystem(@"17.3.1", @"21D61"), NDSystem(@"17.4", @"21E219"),
            NDSystem(@"17.4.1", @"21E236"), NDSystem(@"17.5", @"21F79"),
            NDSystem(@"17.5.1", @"21F90"), NDSystem(@"17.6", @"21G80"),
            NDSystem(@"17.6.1", @"21G93"), NDSystem(@"17.7", @"21H16"),
            NDSystem(@"17.7.1", @"21H216"), NDSystem(@"17.7.2", @"21H221"),
            NDSystem(@"18.0", @"22A3354"), NDSystem(@"18.0.1", @"22A3370"),
            NDSystem(@"18.1", @"22B83"), NDSystem(@"18.1.1", @"22B91"),
            NDSystem(@"18.2", @"22C152"), NDSystem(@"18.2.1", @"22C161"),
            NDSystem(@"18.3", @"22D63"), NDSystem(@"18.3.1", @"22D72"),
            NDSystem(@"18.3.2", @"22D82"), NDSystem(@"18.4", @"22E240"),
            NDSystem(@"18.4.1", @"22E252"), NDSystem(@"18.5", @"22F76"),
            NDSystem(@"18.6", @"22G86"), NDSystem(@"18.6.1", @"22G90"),
            NDSystem(@"18.6.2", @"22G100"), NDSystem(@"18.7", @"22H20"),
            NDSystem(@"18.7.1", @"22H31"), NDSystem(@"18.7.2", @"22H123"),
            NDSystem(@"18.7.9", @"22H355"), NDSystem(@"18.7.10", @"22H374"),
            NDSystem(@"26.4.2", @"23E261"), NDSystem(@"26.5", @"23F77"),
            NDSystem(@"26.5.2", @"23F84"), NDSystem(@"26.6", @"23G71"),
            NDSystem(@"26.6.1", @"23G83"),
        ];
    });
    return profiles;
}

static BOOL NDVersionInRange(NSString *version, NSDictionary *device) {
    NSString *minimum = device[@"minimumOS"];
    NSInteger maximumMajor = [device[@"maximumMajor"] integerValue];
    if ([version compare:minimum options:NSNumericSearch] == NSOrderedAscending) return NO;
    if (version.integerValue > maximumMajor) return NO;
    NSString *machine = device[@"machine"];
    // 18.7.9/18.7.10 为特定安全版本，仅向对应机型推送（与极速版 BDSpoofer 口径一致）。
    if ([version hasPrefix:@"18.7.9"] || [version hasPrefix:@"18.7.10"]) {
        return [machine hasPrefix:@"iPhone11,"];
    }
    // iOS 26 仅支持 iPhone 11（A13）及更新，iPhone XR/XS（iPhone11,x，A12）不支持。
    if (version.integerValue == 26 &&
        ![machine hasPrefix:@"iPhone12,"] && ![machine hasPrefix:@"iPhone13,"] &&
        ![machine hasPrefix:@"iPhone14,"] && ![machine hasPrefix:@"iPhone15,"] &&
        ![machine hasPrefix:@"iPhone16,"] && ![machine hasPrefix:@"iPhone17,"] &&
        ![machine hasPrefix:@"iPhone18,"]) {
        return NO;
    }
    return YES;
}

static NSDictionary *NDRandomSystemForDevice(NSDictionary *device) {
    NSMutableDictionary<NSNumber *, NSMutableArray<NSDictionary *> *> *byMajor = [NSMutableDictionary dictionary];
    for (NSDictionary *profile in NDSystemProfiles()) {
        NSString *version = profile[@"version"];
        if (!NDVersionInRange(version, device)) continue;
        NSNumber *major = @(version.integerValue);
        if (!byMajor[major]) byMajor[major] = [NSMutableArray array];
        [byMajor[major] addObject:profile];
    }
    NSArray<NSNumber *> *majors = [[byMajor allKeys] sortedArrayUsingSelector:@selector(compare:)];
    if (!majors.count) return NDSystemProfiles().firstObject;
    NSNumber *major = majors[arc4random_uniform((uint32_t)majors.count)];
    NSArray *versions = byMajor[major];
    return versions[arc4random_uniform((uint32_t)versions.count)];
}

static NSString *NDRandomHex(NSUInteger count, BOOL uppercase) {
    static const char *hex = "0123456789ABCDEF";
    NSMutableString *value = [NSMutableString stringWithCapacity:count];
    for (NSUInteger i = 0; i < count; i++) {
        [value appendFormat:@"%c", hex[arc4random_uniform(16)]];
    }
    return uppercase ? value : value;
}

// ============================== 配置生成 ==============================

static NSDictionary *NDDefaultTemplate(void) {
    NSString *p = [[NSBundle mainBundle] pathForResource:@"ndspoofer_config" ofType:@"plist"];
    return p ? [NSDictionary dictionaryWithContentsOfFile:p] : nil;
}

// 一键随机：整套身份，所有开关一次开齐，同屏机型 + 独立 IDFV。
static NSDictionary *NDRandomConfigForDevice(NSDictionary *existing, NSDictionary *device) {
    NSDictionary *system = NDRandomSystemForDevice(device);
    NSArray *disks = device[@"disks"];
    NSNumber *disk = disks[arc4random_uniform((uint32_t)disks.count)];
    NSString *deviceName = [NSString stringWithFormat:@"iPhone-%@", NDRandomHex(6, YES)];

    NSMutableDictionary *config = [NDDefaultTemplate() mutableCopy] ?: [NSMutableDictionary dictionary];
    if ([existing isKindOfClass:NSDictionary.class] && existing.count) {
        [config addEntriesFromDictionary:existing];
    }

    // 已有 IDFV 保留（容器内身份稳定）；没有则生成一套。
    if (![config[@"idfv"] isKindOfClass:NSString.class] || ![config[@"idfv"] length]) {
        config[@"idfv"] = NSUUID.UUID.UUIDString.uppercaseString;
    }

    [config addEntriesFromDictionary:@{
        @"configVersion": @1,
        @"generatedAt": @((long long)NSDate.date.timeIntervalSince1970),
        @"enabled": @YES,
        @"spoofSysctl": @YES,
        @"spoofUIDevice": @YES,
        @"spoofBaiduSDK": @YES,
        @"spoofUA": @YES,
        @"spoofIDFV": @YES,
        @"spoofStorage": @YES,
        @"spoofScreen": @YES,
        @"seedPassCustom": @YES,
        @"hwMachine": device[@"machine"],
        @"hwModel": device[@"model"],
        @"marketingName": device[@"marketing"],
        @"cpuBrand": device[@"cpuBrand"],
        @"systemVersion": system[@"version"],
        @"systemBuild": system[@"build"],
        @"memorySize": device[@"memory"],
        @"diskSize": disk,
        @"deviceName": deviceName,
        @"kernHostname": deviceName,
        // 屏幕字段：dylib 仅改写百度统计 EBAppLog 上报值，不 hook UIScreen，布局仍用真机尺寸。
        @"screenWidth": device[@"width"],
        @"screenHeight": device[@"height"],
        @"screenScale": device[@"scale"],
        @"nativeScreenWidth": device[@"nativeWidth"],
        @"nativeScreenHeight": device[@"nativeHeight"],
        @"passSdkVersion": @"9.8.12.20",
    }];
    return config;
}

// 恢复安全：总开关与全部伪装开关关闭，dylib 完全透传。
static NSDictionary *NDSafeConfig(NSDictionary *existing) {
    NSMutableDictionary *config = [NDDefaultTemplate() mutableCopy] ?: [NSMutableDictionary dictionary];
    if ([existing isKindOfClass:NSDictionary.class] && existing.count) {
        [config addEntriesFromDictionary:existing];
    }
    [config addEntriesFromDictionary:@{
        @"configVersion": @1,
        @"enabled": @NO,
        @"spoofSysctl": @NO,
        @"spoofUIDevice": @NO,
        @"spoofBaiduSDK": @NO,
        @"spoofUA": @NO,
        @"spoofIDFV": @NO,
        @"spoofStorage": @NO,
        @"spoofScreen": @NO,
        @"seedPassCustom": @NO,
    }];
    return config;
}

static BOOL NDWriteContainerConfig(NSString *path, NSDictionary *config) {
    if (!path.length || !config.count) return NO;
    NSFileManager *fm = NSFileManager.defaultManager;
    NSError *error = nil;
    if (![fm createDirectoryAtPath:path.stringByDeletingLastPathComponent
       withIntermediateDirectories:YES attributes:@{NSFilePosixPermissions: @0755} error:&error]) return NO;
    NSData *data = [NSPropertyListSerialization dataWithPropertyList:config
                                                              format:NSPropertyListXMLFormat_v1_0
                                                             options:0 error:&error];
    if (!data || ![data writeToFile:path options:NSDataWritingAtomic error:&error]) return NO;
    [fm setAttributes:@{NSFilePosixPermissions: @0644} ofItemAtPath:path error:nil];
    return [[NSDictionary dictionaryWithContentsOfFile:path] isEqualToDictionary:config];
}

// ============================== Crane 加载 ==============================

static NSString *gCraneLoadDetail;

static void NDAddCraneCandidate(NSMutableOrderedSet<NSString *> *candidates, NSString *path) {
    if (path.length) [candidates addObject:path];
}

static void NDAddCraneCandidateFromAppPath(NSMutableOrderedSet<NSString *> *candidates, NSString *appPath) {
    if (!appPath.length) return;
    NSRange marker = [appPath rangeOfString:@"/Applications/" options:NSBackwardsSearch];
    if (marker.location == NSNotFound) return;
    NSString *jailbreakRoot = [appPath substringToIndex:marker.location];
    NDAddCraneCandidate(candidates, [jailbreakRoot stringByAppendingPathComponent:@"usr/lib/libcrane.dylib"]);
}

static void *NDLoadCraneLibrary(void) {
    static void *cachedHandle;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        NSMutableOrderedSet<NSString *> *candidates = [NSMutableOrderedSet orderedSet];
        NSString *bundlePath = NSBundle.mainBundle.bundlePath;
        NDAddCraneCandidateFromAppPath(candidates, bundlePath);
        char resolved[PATH_MAX] = {0};
        if (realpath(bundlePath.fileSystemRepresentation, resolved)) {
            NDAddCraneCandidateFromAppPath(candidates, [NSString stringWithUTF8String:resolved]);
        }
        NDAddCraneCandidate(candidates, @"@rpath/libcrane.dylib");
        NDAddCraneCandidate(candidates, @"libcrane.dylib");
        NDAddCraneCandidate(candidates, @"/usr/lib/libcrane.dylib");
        NDAddCraneCandidate(candidates, @"/var/jb/usr/lib/libcrane.dylib");
        NDAddCraneCandidate(candidates, @"/var/mobile/Library/pkgmirror/usr/lib/libcrane.dylib");

        NSMutableArray<NSString *> *errors = [NSMutableArray array];
        for (NSString *candidate in candidates) {
            dlerror();
            void *handle = dlopen(candidate.fileSystemRepresentation, RTLD_NOW | RTLD_GLOBAL);
            if (handle) { cachedHandle = handle; break; }
            const char *error = dlerror();
            if (error) [errors addObject:[NSString stringWithFormat:@"%@：%s", candidate, error]];
        }
        if (!cachedHandle) {
            gCraneLoadDetail = [NSString stringWithFormat:@"App：%@\n%@", bundlePath,
                                errors.lastObject ?: @"dlopen 没有返回具体错误"];
        }
    });
    return cachedHandle;
}

// ============================== UI ==============================

@interface NDManagerViewController : UITableViewController
@property(nonatomic, strong) CraneManager *crane;
@property(nonatomic, strong) NSArray<NSDictionary *> *containers;
@property(nonatomic, strong) NSMutableSet<NSString *> *selectedContainerIDs;
@property(nonatomic, copy) NSString *displayCurrentContainerID;
@property(nonatomic, copy) NSString *netdiskBaseDataPath;
@property(nonatomic, strong) UIButton *randomButton;
@end

@implementation NDManagerViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    self.title = @"网解";
    self.view.backgroundColor = UIColor.systemGroupedBackgroundColor;
    self.selectedContainerIDs = [NSMutableSet set];
    self.tableView.rowHeight = 84.0;
    self.navigationItem.rightBarButtonItem = [[UIBarButtonItem alloc]
        initWithBarButtonSystemItem:UIBarButtonSystemItemRefresh target:self action:@selector(reloadContainers)];
    [self buildFooter];
    [self reloadContainers];
}

- (void)buildFooter {
    CGFloat width = CGRectGetWidth(self.tableView.bounds);
    UIView *footer = [[UIView alloc] initWithFrame:CGRectMake(0, 0, width, 128)];
    NSArray *titles = @[@"一键随机网盘身份", @"恢复安全（全部关闭）"];
    NSArray *selectors = @[NSStringFromSelector(@selector(randomizeSelected)),
                           NSStringFromSelector(@selector(restoreSafe))];
    for (NSUInteger i = 0; i < titles.count; i++) {
        UIButton *button = [UIButton buttonWithType:UIButtonTypeSystem];
        button.autoresizingMask = UIViewAutoresizingFlexibleWidth;
        button.tag = 2000 + i;
        button.layer.cornerRadius = 12;
        button.layer.masksToBounds = YES;
        button.backgroundColor = i == 0 ? [UIColor colorWithRed:0.86 green:0.18 blue:0.18 alpha:1.0]
                                      : UIColor.secondarySystemGroupedBackgroundColor;
        [button setTitleColor:i == 0 ? UIColor.whiteColor : UIColor.labelColor forState:UIControlStateNormal];
        [button setTitle:titles[i] forState:UIControlStateNormal];
        button.titleLabel.font = [UIFont boldSystemFontOfSize:17];
        button.titleLabel.adjustsFontSizeToFitWidth = YES;
        button.titleLabel.minimumScaleFactor = 0.7;
        [button addTarget:self action:NSSelectorFromString(selectors[i]) forControlEvents:UIControlEventTouchUpInside];
        [footer addSubview:button];
        if (i == 0) self.randomButton = button;
    }
    self.tableView.tableFooterView = footer;
    [self layoutFooter];
}

- (void)layoutFooter {
    UIView *footer = self.tableView.tableFooterView;
    if (!footer) return;
    CGFloat width = CGRectGetWidth(self.tableView.bounds);
    if (fabs(footer.frame.size.width - width) > 0.5) {
        CGRect fr = footer.frame; fr.size.width = width; footer.frame = fr;
        self.tableView.tableFooterView = footer;
    }
    CGFloat side = 18.0, h = 48.0, gap = 10.0;
    CGFloat bw = MAX(0, width - side * 2.0);
    [footer viewWithTag:2000].frame = CGRectMake(side, 8, bw, h);
    [footer viewWithTag:2001].frame = CGRectMake(side, 8 + h + gap, bw, h);
}

- (void)viewDidLayoutSubviews {
    [super viewDidLayoutSubviews];
    [self layoutFooter];
}

// ============================== 容器路径 ==============================

- (NSString *)appPathForContainerID:(NSString *)containerID {
    if (!containerID.length || !self.crane) return nil;
    __block NSString *appPath = nil;
    if ([self.crane respondsToSelector:@selector(enumerate:pathsAssociatedToContainerWithIdentifier:ofApplicationWithIdentifier:)]) {
        [self.crane enumerate:^(NDCraneContainerPathType type, NSString *identifier, NSString *path) {
            if (!appPath && type == NDCraneContainerPathTypeApp && path.length) appPath = [path copy];
        } pathsAssociatedToContainerWithIdentifier:containerID ofApplicationWithIdentifier:NDTargetBundleID];
    }
    if (appPath.length) return appPath;
    if ([self.crane respondsToSelector:@selector(pathsAssociatedToContainerWithIdentifier:ofApplicationWithIdentifier:)]) {
        NSDictionary *paths = [self.crane pathsAssociatedToContainerWithIdentifier:containerID
                                                            ofApplicationWithIdentifier:NDTargetBundleID];
        NSMutableArray *candidates = [NSMutableArray array];
        for (id value in paths.allValues) {
            if ([value isKindOfClass:NSString.class] && [value length]) [candidates addObject:value];
            if ([value isKindOfClass:NSArray.class]) {
                for (id nested in value) {
                    if ([nested isKindOfClass:NSString.class] && [nested length]) [candidates addObject:nested];
                }
            }
        }
        for (NSString *candidate in candidates) {
            if ([candidate containsString:@"/Data/Application/"] ||
                [candidate containsString:@"/Application Support/Crane/"]) return candidate;
        }
        if (candidates.count) return candidates.firstObject;
    }
    return nil;
}

- (NSString *)resolvedBaseDataPath {
    if (self.netdiskBaseDataPath.length) return self.netdiskBaseDataPath;
    Class proxyClass = NSClassFromString(@"LSApplicationProxy");
    if ([proxyClass respondsToSelector:@selector(applicationProxyForIdentifier:)]) {
        LSApplicationProxy *proxy = [(id)proxyClass applicationProxyForIdentifier:NDTargetBundleID];
        NSString *path = proxy.dataContainerURL.path;
        if (path.length) self.netdiskBaseDataPath = path;
    }
    if (!self.netdiskBaseDataPath.length) {
        NSArray *identifiers = [self.crane containerIdentifiersOfApplicationWithIdentifier:NDTargetBundleID] ?: @[];
        for (NSString *identifier in identifiers) {
            if (![identifier isKindOfClass:NSString.class] || !identifier.length) continue;
            NSString *candidate = [self appPathForContainerID:identifier];
            if (!candidate.length) continue;
            NSRange marker = [candidate rangeOfString:@"/Library/___Crane_Containers/"];
            if (marker.location != NSNotFound) {
                candidate = [candidate substringToIndex:marker.location];
            }
            if ([candidate containsString:@"/Containers/Data/Application/"]) {
                self.netdiskBaseDataPath = candidate;
                break;
            }
        }
    }
    return self.netdiskBaseDataPath;
}

- (NSString *)configPathForContainerID:(NSString *)containerID {
    NSString *base = [self resolvedBaseDataPath];
    if (!base.length || !containerID.length) return nil;
    NSString *containerPath = base;
    if (![containerID.uppercaseString isEqualToString:@"DEFAULT"]) {
        containerPath = [[[base stringByAppendingPathComponent:@"Library"]
            stringByAppendingPathComponent:@"___Crane_Containers"]
            stringByAppendingPathComponent:containerID];
    }
    return [[containerPath stringByAppendingPathComponent:@"Documents"]
        stringByAppendingPathComponent:NDConfigFileName];
}

- (void)showMessage:(NSString *)title detail:(NSString *)detail {
    dispatch_async(dispatch_get_main_queue(), ^{
        UIAlertController *alert = [UIAlertController alertControllerWithTitle:title
                                                                       message:detail
                                                                preferredStyle:UIAlertControllerStyleAlert];
        [alert addAction:[UIAlertAction actionWithTitle:@"好" style:UIAlertActionStyleDefault handler:nil]];
        [self presentViewController:alert animated:YES completion:nil];
    });
}

- (void)reloadContainers {
    self.randomButton.enabled = NO;
    self.netdiskBaseDataPath = nil;
    void *handle = NDLoadCraneLibrary();
    Class managerClass = NSClassFromString(@"CraneManager");
    if (!handle || !managerClass || ![managerClass respondsToSelector:@selector(sharedManager)]) {
        self.containers = @[];
        [self.tableView reloadData];
        [self showMessage:@"无法加载 Crane"
                   detail:[NSString stringWithFormat:@"没有找到兼容的 libcrane.dylib，请确认 Crane 1.3.14-6 已安装并启用。\n\n%@",
                           gCraneLoadDetail ?: @"没有加载诊断"]];
        return;
    }
    self.crane = [managerClass sharedManager];
    if (![self.crane isApplicationSupportedByCrane:NDTargetBundleID]) {
        self.containers = @[];
        [self.tableView reloadData];
        [self showMessage:@"百度网盘尚未启用 Crane" detail:@"请先在 Crane 中为百度网盘创建至少一个容器。"];
        return;
    }

    NSArray *identifiers = [self.crane containerIdentifiersOfApplicationWithIdentifier:NDTargetBundleID] ?: @[];
    NSString *actuallyActive = [self.crane activeContainerIdentifierForApplicationWithIdentifier:NDTargetBundleID];
    NSString *configuredDefault = nil, *systemDefault = nil;
    NSMutableArray *rows = [NSMutableArray array];
    for (id raw in identifiers) {
        if (![raw isKindOfClass:NSString.class] || ![(NSString *)raw length]) continue;
        NSString *containerID = raw;
        if ([containerID.uppercaseString isEqualToString:@"DEFAULT"]) systemDefault = containerID;
        NSString *rawName = [self.crane displayNameForContainerWithIdentifier:containerID
                                                      ofApplicationWithIdentifier:NDTargetBundleID
                                                            shouldUseShortVersion:NO];
        NSString *name = rawName.length ? rawName : containerID;
        for (NSString *suffix in @[@"（默认）", @"(默认)", @"（Default）", @"(Default)"]) {
            if ([name hasSuffix:suffix] && name.length > suffix.length) {
                configuredDefault = containerID;
                name = [name substringToIndex:name.length - suffix.length];
                name = [name stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
                break;
            }
        }
        NSString *path = [self configPathForContainerID:containerID];
        NSDictionary *config = path.length ? [NSDictionary dictionaryWithContentsOfFile:path] : nil;
        NSString *summary;
        if ([config[@"enabled"] boolValue]) {
            summary = [NSString stringWithFormat:@"%@（%@）· iOS %@\n营销名 %@ · %ldGB · %ldGB内存",
                       config[@"deviceProfileName"] ?: config[@"hwMachine"] ?: @"未知",
                       config[@"hwMachine"] ?: @"未知",
                       config[@"systemVersion"] ?: @"未知",
                       config[@"marketingName"] ?: @"-",
                       (long)[config[@"diskSize"] integerValue],
                       (long)[config[@"memorySize"] integerValue]];
        } else {
            summary = config ? @"伪装已关闭（安全）" : @"未配置";
        }
        [rows addObject:@{@"id": containerID, @"name": name ?: containerID,
                          @"summary": summary, @"path": path ?: @""}];
    }
    [rows sortUsingComparator:^NSComparisonResult(NSDictionary *a, NSDictionary *b) {
        return [a[@"name"] localizedStandardCompare:b[@"name"]];
    }];
    self.displayCurrentContainerID = configuredDefault ?: systemDefault ?: actuallyActive;
    self.containers = rows;
    [self.selectedContainerIDs intersectSet:[NSSet setWithArray:[rows valueForKey:@"id"]]];
    self.randomButton.enabled = rows.count > 0;
    [self.tableView reloadData];
}

- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section {
    return self.containers.count;
}

- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath {
    static NSString *identifier = @"NDContainerCell";
    UITableViewCell *cell = [tableView dequeueReusableCellWithIdentifier:identifier];
    if (!cell) cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleSubtitle reuseIdentifier:identifier];
    NSDictionary *row = self.containers[indexPath.row];
    NSString *containerID = row[@"id"];
    BOOL selected = [self.selectedContainerIDs containsObject:containerID];
    BOOL active = [containerID isEqualToString:self.displayCurrentContainerID];
    NSString *suffix = @"（当前）";
    NSString *title = active ? [NSString stringWithFormat:@"%@%@", row[@"name"], suffix] : row[@"name"];
    NSMutableAttributedString *styled = [[NSMutableAttributedString alloc] initWithString:title];
    if (active) {
        [styled addAttribute:NSForegroundColorAttributeName value:UIColor.systemRedColor
                        range:NSMakeRange(title.length - suffix.length, suffix.length)];
    }
    cell.textLabel.attributedText = styled;
    cell.detailTextLabel.text = row[@"summary"];
    cell.detailTextLabel.numberOfLines = 2;
    cell.accessoryType = selected ? UITableViewCellAccessoryCheckmark : UITableViewCellAccessoryNone;
    return cell;
}

- (void)tableView:(UITableView *)tableView didSelectRowAtIndexPath:(NSIndexPath *)indexPath {
    [tableView deselectRowAtIndexPath:indexPath animated:YES];
    NSString *containerID = self.containers[indexPath.row][@"id"];
    if ([self.selectedContainerIDs containsObject:containerID]) {
        [self.selectedContainerIDs removeObject:containerID];
    } else {
        [self.selectedContainerIDs addObject:containerID];
    }
    [tableView reloadRowsAtIndexPaths:@[indexPath] withRowAnimation:UITableViewRowAnimationAutomatic];
}

// ============================== 动作 ==============================

- (void)applyToSelected:(BOOL)random {
    if (!self.selectedContainerIDs.count) {
        [self showMessage:@"尚未选择容器" detail:@"请先勾选需要配置的 Crane 容器。"];
        return;
    }
    NSArray<NSDictionary *> *devices = NDDeviceProfiles();
    NSMutableArray<NSString *> *ok = [NSMutableArray array];
    NSMutableArray<NSString *> *fail = [NSMutableArray array];
    for (NSDictionary *row in self.containers) {
        NSString *containerID = row[@"id"];
        if (![self.selectedContainerIDs containsObject:containerID]) continue;
        NSString *path = row[@"path"];
        NSDictionary *existing = [NSDictionary dictionaryWithContentsOfFile:path];
        NSDictionary *config;
        if (random) {
            // 每个容器独立抽一套，避免相邻容器同身份。
            NSDictionary *device = devices[arc4random_uniform((uint32_t)devices.count)];
            config = NDRandomConfigForDevice(existing, device);
            // 管理器展示用名（与 dylib 无关）
            NSMutableDictionary *m = config.mutableCopy;
            m[@"deviceProfileName"] = device[@"name"];
            config = m;
        } else {
            config = NDSafeConfig(existing);
        }
        if (NDWriteContainerConfig(path, config)) {
            [ok addObject:row[@"name"]];
        } else {
            [fail addObject:row[@"name"]];
        }
    }
    [self reloadContainers];
    if (random) {
        [self showMessage:@"随机完成"
                   detail:[NSString stringWithFormat:@"已写入 %lu 个容器：%@%@",
                           (unsigned long)ok.count,
                           [ok componentsJoinedByString:@"、"],
                           fail.count ? [NSString stringWithFormat:@"\n失败：%@", [fail componentsJoinedByString:@"、"]] : @""]];
    } else {
        [self showMessage:@"已恢复安全"
                   detail:fail.count ? [NSString stringWithFormat:@"部分失败：%@", [fail componentsJoinedByString:@"、"]]
                                     : @"选中容器的伪装已全部关闭。"];
    }
}

- (void)randomizeSelected { [self applyToSelected:YES]; }
- (void)restoreSafe { [self applyToSelected:NO]; }

@end

@interface NDAppDelegate : UIResponder <UIApplicationDelegate>
@property(nonatomic, strong) UIWindow *window;
@end

@implementation NDAppDelegate
- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions {
    self.window = [[UIWindow alloc] initWithFrame:UIScreen.mainScreen.bounds];
    NDManagerViewController *vc = [[NDManagerViewController alloc] initWithStyle:UITableViewStyleInsetGrouped];
    UINavigationController *nav = [[UINavigationController alloc] initWithRootViewController:vc];
    self.window.rootViewController = nav;
    [self.window makeKeyAndVisible];
    return YES;
}
@end

int main(int argc, char *argv[]) {
    @autoreleasepool {
        return UIApplicationMain(argc, argv, nil, NSStringFromClass(NDAppDelegate.class));
    }
}
