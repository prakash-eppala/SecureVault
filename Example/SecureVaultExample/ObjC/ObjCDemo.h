//
//  ObjCDemo.h
//  SecureVaultExample
//
//  Created by Prakash on 09/10/26.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/// Uses SecureVault from Objective-C: values, policies, records, files and errors.
@interface ObjCDemo : NSObject

/// Runs every step and reports one line per step on the main queue.
+ (void)runWithCompletion:(NS_SWIFT_UI_ACTOR void (^)(NSArray<NSString *> *lines))completion;

@end

NS_ASSUME_NONNULL_END
