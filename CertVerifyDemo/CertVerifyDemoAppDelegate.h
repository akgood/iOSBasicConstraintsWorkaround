//
//  CertVerifyDemoAppDelegate.h
//  CertVerifyDemo
//
//  Created by Adam Goodman on 8/11/11.
//  Copyright 2011 Duo Security. All rights reserved.
//

#import <UIKit/UIKit.h>

@class CertVerifyDemoViewController;

@interface CertVerifyDemoAppDelegate : NSObject <UIApplicationDelegate> {

}

@property (nonatomic, retain) IBOutlet UIWindow *window;

@property (nonatomic, retain) IBOutlet CertVerifyDemoViewController *viewController;

@end
