//
//  CertVerifyDemoViewController.h
//  CertVerifyDemo
//
//  Created by Adam Goodman on 8/11/11.
//  Copyright 2011 Duo Security. All rights reserved.
//

#import <UIKit/UIKit.h>

@interface CertVerifyDemoViewController : UIViewController {
    UITextField *urlField;
    UITextView *resultView;
}
- (IBAction)sendRequest:(id)sender;

@property (nonatomic, retain) IBOutlet UITextField *urlField;
@property (nonatomic, retain) IBOutlet UITextView *resultView;
@end
