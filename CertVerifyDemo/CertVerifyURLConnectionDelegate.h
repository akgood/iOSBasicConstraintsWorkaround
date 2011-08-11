//
//  CertVerifyURLConnectionDelegate.h
//  CertVerifyDemo
//
//  Created by Adam Goodman on 8/11/11.
//  Copyright 2011 Duo Security. All rights reserved.
//

#import <Foundation/Foundation.h>


@interface CertVerifyURLConnectionDelegate : NSObject {
    
}
- (BOOL)connection:(NSURLConnection *)connection canAuthenticateAgainstProtectionSpace:(NSURLProtectionSpace *)protectionSpace;
- (void)connection:(NSURLConnection *)connection didReceiveAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge;
@end
