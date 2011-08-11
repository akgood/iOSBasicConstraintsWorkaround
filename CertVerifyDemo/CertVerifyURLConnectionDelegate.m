//
//  CertVerifyURLConnectionDelegate.m
//  CertVerifyDemo
//
//  Created by Adam Goodman on 8/11/11.
//  Copyright 2011 Duo Security. All rights reserved.
//

#import "CertVerifyURLConnectionDelegate.h"

#import <Security/Security.h>
#import <openssl/x509.h>
#import <openssl/bio.h>
#import <openssl/err.h>

static void logOpenSSLErrors(void);
static X509 *createX509FromCertRef(SecCertificateRef ref);
static bool verifyWithOpenSSL(SecTrustRef trust);

static void logOpenSSLErrors(void) {
    // Wrapper function to print out any current OpenSSL errors via NSLog
    // We could probably also just do ERR_print_errors_fp(stderr), but trying
    // to stick to the standard Cocoa interface here...

    // Print errors into a memory buffer
    BIO *errBio = BIO_new(BIO_s_mem());
    ERR_print_errors(errBio);
    
    // Get the pointer to the buffer
    void *bytes;
    int len = BIO_get_mem_data(errBio, &bytes);
    
    // Attempt to convert buffer to an NSString
    NSData *data = [[NSData alloc] initWithBytesNoCopy:bytes length:len freeWhenDone:NO];
    NSString *errorMessages = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    if (errorMessages && [errorMessages length]) {
        NSLog(@"%@", errorMessages);
        [errorMessages release];
    }
    [data release];
    BIO_free(errBio);
}

static X509 *createX509FromCertRef(SecCertificateRef ref) {
    // Copy the DER data out of the SecCertificateRef, then parse it
    // into an OpenSSL X509* structure
    
    CFDataRef data = SecCertificateCopyData(ref);
    X509 *x509cert = NULL;
    if (data) {
        BIO *mem = BIO_new_mem_buf((void *)CFDataGetBytePtr(data), CFDataGetLength(data));
        x509cert = d2i_X509_bio(mem, NULL);
        BIO_free(mem);
        CFRelease(data);

        if (!x509cert) {
            NSLog(@"OpenSSL couldn't parse X509 Certificate");
            logOpenSSLErrors();
        }
    } else {
        NSLog(@"Failed to retrieve DER data from Certificate Ref");
    }
    return x509cert;
}

static bool verifyWithOpenSSL(SecTrustRef trust) {  
    bool ret = FALSE;
    X509 *leaf = NULL;
    STACK_OF(X509) *trusted_chain = NULL;
    STACK_OF(X509) *untrusted_chain = NULL;
    X509_STORE_CTX *csc = NULL;
    
    int chain_len = SecTrustGetCertificateCount(trust);
    if (chain_len < 2) {
        // This code is intended for chains which contain at least a root certificate
        // and a leaf certificate. It may be possible to have a leaf certificate that
        // is directly trusted by the system (and e.g. self-signed).
        // In this case, we probably don't have to worry about basicConstraints, because
        // there are no intermediate (or root) CA's involved. So we'll defer to the system's
        // judgment on this one...
        NSLog(@"Warning: Certificate chain contains fewer than two certificates!");
        return true;
    }
    // get leaf certificate
    // (i.e. the first certificate in the chain provided by the iOS Security Framework)
    SecCertificateRef leafRef = SecTrustGetCertificateAtIndex(trust, 0);
    leaf = createX509FromCertRef(leafRef);
    if (!leaf) {
        goto cleanup;
    }
    
    // Create a 'trusted' chain structure containing just the anchor certificate
    // (i.e. the last certificate in the chain provided by the iOS Security Framework)
    SecCertificateRef anchorRef = SecTrustGetCertificateAtIndex(trust, chain_len - 1);
    X509 *anchor = createX509FromCertRef(anchorRef);
    if (!anchor) {
        goto cleanup;
    }
    trusted_chain = sk_X509_new(NULL);
    sk_X509_push(trusted_chain, anchor);
    
    // Get any intermediate certificates and store them in an 'untrusted' chain structure
    // (any remaining certificates in the chain provided by the iOS Security Framework)
    untrusted_chain = sk_X509_new(NULL);
    for (int i = 1; i < (chain_len - 1); i++) {
        SecCertificateRef ref = SecTrustGetCertificateAtIndex(trust, i);
        X509 *cert = createX509FromCertRef(ref);
        if (!cert) {
            goto cleanup;
        }
        sk_X509_push(untrusted_chain, cert);
    }
    
    // Build a context for certificate verification
    csc = X509_STORE_CTX_new();
    if (!csc) {
        logOpenSSLErrors();
        goto cleanup;
    }
    if (!X509_STORE_CTX_init(csc, NULL, leaf, untrusted_chain)) {
        logOpenSSLErrors();
        goto cleanup;
    }
    X509_STORE_CTX_trusted_stack(csc, trusted_chain);
    
    // Run verification
    int i = X509_verify_cert(csc);
    if (i > 0) {
        NSLog(@"OpenSSL chain validation succeeded");
        ret = TRUE;
    } else {
        NSLog(@"OpenSSL chain validation failed");
        logOpenSSLErrors();
    }
    
cleanup:
    if (csc) {
        X509_STORE_CTX_free(csc);
    }
    if (trusted_chain) {
        sk_X509_pop_free(trusted_chain, X509_free);
    }
    if (untrusted_chain) {
        sk_X509_pop_free(untrusted_chain, X509_free);
    }
    if (leaf) {
        X509_free(leaf);
    }
    
    return ret;
}

@implementation CertVerifyURLConnectionDelegate

- (BOOL)connection:(NSURLConnection *)connection canAuthenticateAgainstProtectionSpace:(NSURLProtectionSpace *)protectionSpace {
    // Indicate that for 'ServerTrust' authentication methods, the URL loading system
    // *should* call our connection:didReceiveAuthenticationChallenge: delegate method
    // rather than just validating everything internally
    
    // One possible improvement would be to check the value of:
    //
    // [[UIDevice currentDevice] systemVersion]
    //
    // to see whether we're running on a vulnerable version of iOS.
    // This workaround (at least, in its current form) provides much less-friendly
    // error-handling for certificate errors than the system normally does
    // (more details below), so it would be best to disable it on properly-patched
    // iOS versions.
    return [protectionSpace.authenticationMethod isEqualToString:NSURLAuthenticationMethodServerTrust];
}

- (void)connection:(NSURLConnection *)connection didReceiveAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge {
    if ([challenge.protectionSpace.authenticationMethod isEqualToString:NSURLAuthenticationMethodServerTrust]) {
        // By now, the OS will already have built a SecTrustRef instance for
        // the server certificates; we just need to evaluate it
        SecTrustRef serverTrust = challenge.protectionSpace.serverTrust;
        SecTrustResultType res;
        OSStatus status = SecTrustEvaluate(serverTrust, &res);

        bool verified = FALSE;
        if (status == errSecSuccess && ((res == kSecTrustResultProceed) || (res == kSecTrustResultUnspecified))) {
            NSLog(@"iOS certificate chain validation for host %@ passed", challenge.protectionSpace.host);
            // If the iOS Security Framework accepted the certificate chain, we'll
            // check the chain *again* with OpenSSL. This is a relatively simplistic
            // implementation - for example, it won't check hostnames - but we assume
            // that the only gap we need to cover is basicConstraints checking, and
            // OpenSSL *will* do that.
            verified = verifyWithOpenSSL(serverTrust);
        } else {
            NSLog(@"iOS certificate chain validation for host %@ failed", challenge.protectionSpace.host);
        }
        
        if (verified) {
            // If *both* verifications succeeded, then continue with the connection
            NSURLCredential *successCredential = [NSURLCredential credentialForTrust:challenge.protectionSpace.serverTrust];
            [challenge.sender useCredential:successCredential
                 forAuthenticationChallenge:challenge];
        } else {
            // If verification did not succeed, then cancel the connection
            // Calling cancelAuthenticationChallenge will abort the connection, but
            // it will cause the system to return a very generic error message to
            // the delegate. As an alternative, we might be able to do something like:
            //
            // [connection cancel];
            // [self connection:connection didFailWithError:[NSError errorWith...]];
            //
            // and provide a more-detailed error message. Replicating all of Apple's
            // certificate-error handling would likely be difficult, though.
            [challenge.sender cancelAuthenticationChallenge:challenge];
        }
    } else {
        // otherwise, attempt to bypass the authentication challenge logic.
        // (this code probably isn't reachable anyway, given the contents
        // of the connection:canAuthenticateAgainstProtectionSpace: method) 
        [challenge.sender continueWithoutCredentialForAuthenticationChallenge:challenge];
    }
}
@end
