//
//  SVVaultObjCTests.m
//  SecureVaultObjCTests
//
//  Created by Prakash on 09/10/26.
//

@import XCTest;
@import SecureVault;

// SVVault never stores completion blocks; clang flags `set…` selectors heuristically.
#pragma clang diagnostic ignored "-Warc-retain-cycles"

@interface SVVaultObjCTests : XCTestCase
@property (nonatomic, strong) SVVault *vault;
@end

@implementation SVVaultObjCTests

- (void)setUp {
    self.vault = [SVVault inMemoryVaultForTesting];
}

- (void)testStringRoundTripAndMainQueueDelivery {
    SVVault *vault = self.vault;
    XCTestExpectation *done = [self expectationWithDescription:@"round trip"];
    [vault setString:@"tok_objc" forKey:@"accessToken" namespace:@"auth" policy:SVPolicy.accessToken completion:^(NSError *error) {
        XCTAssertNil(error);
        XCTAssertTrue(NSThread.isMainThread);
        [vault stringForKey:@"accessToken" namespace:@"auth" completion:^(NSString *value, NSError *readError) {
            XCTAssertNil(readError);
            XCTAssertEqualObjects(value, @"tok_objc");
            [done fulfill];
        }];
    }];
    [self waitForExpectations:@[done] timeout:5];
}

- (void)testVersion {
    XCTAssertEqualObjects(SVVault.sdkVersion, @"1.0.1");
    XCTAssertEqual(SVVault.sdkBuild, 2);
}

- (void)testMissingValueReportsItemNotFound {
    SVVault *vault = self.vault;
    XCTestExpectation *done = [self expectationWithDescription:@"missing"];
    [vault dataForKey:@"absent" namespace:nil completion:^(NSData *value, NSError *error) {
        XCTAssertNil(value);
        XCTAssertEqualObjects(error.domain, SVError.domain);
        XCTAssertEqual(error.code, SVErrorCodeItemNotFound);
        [done fulfill];
    }];
    [self waitForExpectations:@[done] timeout:5];
}

- (void)testSecureCodingObjectsAndNumbers {
    SVVault *vault = self.vault;
    XCTestExpectation *done = [self expectationWithDescription:@"objects"];
    NSDictionary *profile = @{@"name": @"Asha", @"age": @41};
    [vault setObject:profile forKey:@"profile" namespace:@"user" policy:nil completion:^(NSError *error) {
        XCTAssertNil(error);
        [vault objectOfClasses:@[NSDictionary.class, NSString.class, NSNumber.class] forKey:@"profile" namespace:@"user" completion:^(id object, NSError *readError) {
            XCTAssertNil(readError);
            XCTAssertEqualObjects(object, profile);
            [vault setNumber:@42 forKey:@"answer" namespace:nil policy:SVPolicy.preference completion:^(NSError *numberError) {
                XCTAssertNil(numberError);
                [vault numberForKey:@"answer" namespace:nil completion:^(NSNumber *number, NSError *e) {
                    XCTAssertEqualObjects(number, @42);
                    [done fulfill];
                }];
            }];
        }];
    }];
    [self waitForExpectations:@[done] timeout:5];
}

- (void)testPolicyCopyAndFailClosed {
    SVVault *vault = self.vault;
    SVPolicy *policy = [SVPolicy.highlySensitive copy];
    policy.deviceOnly = NO; // rule R2: highly sensitive data cannot be backed up
    XCTestExpectation *done = [self expectationWithDescription:@"policy"];
    [vault setString:@"x" forKey:@"k" namespace:nil policy:policy completion:^(NSError *error) {
        XCTAssertEqual(error.code, SVErrorCodeSecurityPolicyViolation);
        XCTAssertTrue(SVPolicy.highlySensitive.deviceOnly, @"presets are not mutated by copies");
        [done fulfill];
    }];
    [self waitForExpectations:@[done] timeout:5];
}

- (void)testDatabaseRecords {
    SVVault *vault = self.vault;
    XCTestExpectation *done = [self expectationWithDescription:@"database"];
    [vault databaseNamed:@"medical" policy:nil completion:^(SVDatabase *db, NSError *error) {
        XCTAssertNil(error);
        [db putRecord:@{@"name": @"Bob", @"age": @17} withID:@"p1" type:@"Patient" completion:^(NSError *putError) {
            XCTAssertNil(putError);
            [db recordWithID:@"p1" type:@"Patient" completion:^(NSDictionary *record, NSError *getError) {
                XCTAssertNil(getError);
                XCTAssertEqualObjects(record[@"name"], @"Bob");
                [db recordWithID:@"missing" type:@"Patient" completion:^(NSDictionary *none, NSError *missingError) {
                    XCTAssertNil(none);
                    XCTAssertNil(missingError);
                    [done fulfill];
                }];
            }];
        }];
    }];
    [self waitForExpectations:@[done] timeout:5];
}

- (void)testFilesAndLogout {
    SVVault *vault = self.vault;
    XCTestExpectation *done = [self expectationWithDescription:@"files"];
    NSData *pdf = [@"%PDF-1.7 fake" dataUsingEncoding:NSUTF8StringEncoding];
    [vault.fileStore writeData:pdf named:@"report.pdf" namespace:@"cache" policy:nil completion:^(NSError *error) {
        XCTAssertNil(error);
        [vault.fileStore readDataNamed:@"report.pdf" namespace:@"cache" completion:^(NSData *data, NSError *readError) {
            XCTAssertEqualObjects(data, pdf);
            [vault logoutWithCompletion:^(NSError *logoutError) {
                XCTAssertNil(logoutError);
                [vault.fileStore listFilesInNamespace:@"cache" completion:^(NSArray<NSString *> *names, NSError *listError) {
                    XCTAssertEqual(names.count, 0u);
                    [done fulfill];
                }];
            }];
        }];
    }];
    [self waitForExpectations:@[done] timeout:5];
}

@end
