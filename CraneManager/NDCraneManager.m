//
//  NDCraneManager.m  —  网盘解（卍解）：为百度网盘的 Crane 容器逐容器写入 NDSpoofer 配置
//
//  版本：9.20-05
//
//  用法：多选容器 → 一键随机网盘身份（每个容器一套独立机型/系统/IDFV）。
//  机型池只包含与真机同屏（375x667 @2x）的 iPhone 8 / iPhone SE3，避免机型与屏幕矛盾。
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
                              NSInteger memory, NSArray<NSNumber *> *disks,
                              NSString *minimumOS, NSInteger maximumMajor) {
    return @{
        @"name": name, @"machine": machine, @"model": model,
        @"marketing": marketing, @"cpuBrand": cpuBrand,
        // 两机均为 375x667 @2x / 750x1334，与 SE2 真机完全一致
        @"width": @375, @"height": @667,
        @"nativeWidth": @750, @"nativeHeight": @1334, @"scale": @2,
        @"memory": @(memory), @"disks": disks,
        @"minimumOS": minimumOS, @"maximumMajor": @(maximumMajor)
    };
}

static NSArray<NSDictionary *> *NDDeviceProfiles(void) {
    static NSArray *profiles;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        profiles = @[
            NDDevice(@"iPhone 8", @"iPhone10,1", @"D20AP", @"iPhone8",
                     @"Apple A11 Bionic", 2048, @[@64], @"15.0", 16),
            NDDevice(@"iPhone SE (3rd generation)", @"iPhone14,6", @"D49AP", @"iPhoneSE3",
                     @"Apple A15 Bionic", 4096, @[@64, @128, @256], @"15.4", 18),
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
            NDSystem(@"18.6.2", @"22G100"),
        ];
    });
    return profiles;
}

static BOOL NDVersionInRange(NSString *version, NSDictionary *device) {
    NSString *minimum = device[@"minimumOS"];
    NSInteger maximumMajor = [device[@"maximumMajor"] integerValue];
    if ([version compare:minimum options:NSNumericSearch] == NSOrderedAscending) return NO;
    if (version.integerValue > maximumMajor) return NO;
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
        // 屏幕字段仅用于管理器展示；dylib 不 hook UIScreen（两机与真机同屏）
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
    self.title = @"网盘解";
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
