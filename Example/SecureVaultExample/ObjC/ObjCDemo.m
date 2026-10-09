//
//  ObjCDemo.m
//  SecureVaultExample
//
//  Created by Prakash on 09/10/26.
//

#import "ObjCDemo.h"
@import SecureVault;

// SVVault never stores completion blocks; clang flags `set…` selectors heuristically.
#pragma clang diagnostic ignored "-Warc-retain-cycles"

@implementation ObjCDemo

+ (void)runWithCompletion:(NS_SWIFT_UI_ACTOR void (^)(NSArray<NSString *> *lines))completion {
    SVVault *vault = SVVault.sharedVault;
    NSMutableArray<NSString *> *lines = [NSMutableArray array];
    [lines addObject:[NSString stringWithFormat:@"SecureVault %@ (build %ld)", SVVault.sdkVersion, (long)SVVault.sdkBuild]];

    SVPolicy *shortLived = [SVPolicy.accessToken copy];
    shortLived.expiresAfter = 3600;

    [vault setString:@"objc-token" forKey:@"objcToken" namespace:@"auth" policy:shortLived completion:^(NSError *error) {
        [lines addObject:error ? error.localizedDescription : @"Stored a token with a one-hour lifetime"];

        [vault stringForKey:@"objcToken" namespace:@"auth" completion:^(NSString *token, NSError *readError) {
            [lines addObject:[NSString stringWithFormat:@"Read back: %@", token ?: readError.localizedDescription]];

            [vault stringForKey:@"missing" namespace:nil completion:^(NSString *none, NSError *missing) {
                BOOL notFound = [missing.domain isEqualToString:SVError.domain] && missing.code == SVErrorCodeItemNotFound;
                [lines addObject:notFound ? @"Missing key reports SVErrorCodeItemNotFound" : @"Unexpected result for a missing key"];

                [vault setObject:@{@"plan": @"premium", @"seats": @5} forKey:@"subscription" namespace:@"user" policy:nil completion:^(NSError *objectError) {
                    [vault objectOfClasses:@[NSDictionary.class, NSString.class, NSNumber.class] forKey:@"subscription" namespace:@"user"
                                completion:^(id object, NSError *readObjectError) {
                        [lines addObject:[NSString stringWithFormat:@"Secure-coded dictionary: %@", object ?: readObjectError.localizedDescription]];

                        [vault databaseNamed:@"medical" policy:SVPolicy.highlySensitive completion:^(SVDatabase *db, NSError *dbError) {
                            NSString *patientID = NSUUID.UUID.UUIDString;
                            NSDictionary *patient = @{@"id": patientID, @"name": @"Kabir Das", @"condition": @"Asthma", @"age": @29};
                            [db putRecord:patient withID:patientID type:@"Patient" completion:^(NSError *putError) {
                                [db countRecordsOfType:@"Patient" completion:^(NSInteger count, NSError *countError) {
                                    [lines addObject:[NSString stringWithFormat:@"Database has %ld patients (Swift sees this one too)", (long)count]];

                                    NSData *note = [@"Written from Objective-C" dataUsingEncoding:NSUTF8StringEncoding];
                                    [vault.fileStore writeData:note named:@"objc-note.txt" namespace:@"medical" policy:nil completion:^(NSError *fileError) {
                                        [vault.fileStore listFilesInNamespace:@"medical" completion:^(NSArray<NSString *> *names, NSError *listError) {
                                            [lines addObject:[NSString stringWithFormat:@"Files: %@", [names componentsJoinedByString:@", "]]];

                                            [vault securityReportWithCompletion:^(NSDictionary *report, NSError *reportError) {
                                                NSArray *findings = report[@"findings"];
                                                [lines addObject:[NSString stringWithFormat:@"Security report: %lu finding(s)", (unsigned long)findings.count]];
                                                completion(lines);
                                            }];
                                        }];
                                    }];
                                }];
                            }];
                        }];
                    }];
                }];
            }];
        }];
    }];
}

@end
