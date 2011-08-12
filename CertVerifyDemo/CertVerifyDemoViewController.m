//
//  CertVerifyDemoViewController.m
//  CertVerifyDemo
//
//  Created by Adam Goodman on 8/11/11.
//  Copyright 2011 Duo Security. All rights reserved.
//

#import "CertVerifyDemoViewController.h"
#import "CertVerifyURLConnectionDelegate.h"

#pragma mark - Private Interface
@interface CertVerifyDemoViewController ()
- (void)connectionFailed:(NSError *)error;
- (void)connectionDoneWithResponse:(NSURLResponse *)response
                              data:(NSData *)data;
@end

#pragma mark - Custom URLConnectionDelegate Interface
@interface MyConnectionDelegate : CertVerifyURLConnectionDelegate {
    CertVerifyDemoViewController *controller;
    NSMutableData *receivedData;
    NSURLResponse *response;
}
- (id)initWithController:(CertVerifyDemoViewController *)controller;
- (void)dealloc;
- (void)connection:(NSURLConnection *)connection didFailWithError:(NSError *)error;
- (void)connection:(NSURLConnection *)connection didReceiveResponse:(NSURLResponse *)response_in;
- (void)connection:(NSURLConnection *)connection didReceiveData:(NSData *)data;
- (void)connectionDidFinishLoading:(NSURLConnection *)connection;
@end

#pragma mark - CertVerifyDemoViewController implementation
@implementation CertVerifyDemoViewController
@synthesize urlField;
@synthesize resultView;

- (void)dealloc
{
    [super dealloc];
}

- (void)didReceiveMemoryWarning
{
    // Releases the view if it doesn't have a superview.
    [super didReceiveMemoryWarning];
    
    // Release any cached data, images, etc that aren't in use.
}

#pragma mark - View lifecycle

/*
// Implement viewDidLoad to do additional setup after loading the view, typically from a nib.
- (void)viewDidLoad
{
    [super viewDidLoad];
}
*/

- (void)viewDidUnload
{
    [super viewDidUnload];
    // Release any retained subviews of the main view.
    // e.g. self.myOutlet = nil;
}

- (BOOL)shouldAutorotateToInterfaceOrientation:(UIInterfaceOrientation)interfaceOrientation
{
    // Return YES for supported orientations
    return (interfaceOrientation == UIInterfaceOrientationPortrait);
}

#pragma mark - UITextFieldDelegate
- (bool)textFieldShouldReturn:(UITextField *)textField
{
    [textField resignFirstResponder];
    [self sendRequest:self];
    return YES;
}

#pragma mark - Received Actions

- (IBAction)sendRequest:(id)sender
{
    MyConnectionDelegate *delegate = [[MyConnectionDelegate alloc] initWithController:self];
    NSURLRequest *request = [NSURLRequest requestWithURL:[NSURL URLWithString:[urlField text]]];
    NSURLConnection *connection = [NSURLConnection connectionWithRequest:request delegate:delegate];
    [connection start];
    [delegate release];
}

#pragma mark - URL Connection Result Handling
- (void)connectionFailed:(NSError *)error
{
    self.resultView.text = [NSString stringWithFormat:@"Request Failed:\n\n%@", error];
}

- (void)connectionDoneWithResponse:(NSURLResponse *)response
                              data:(NSData *)data
{
    // get the HTTP status code (if we were using HTTP)
    NSString *responseString = @"Received Response:";
    if ([response isKindOfClass:[NSHTTPURLResponse class]]) {
        NSHTTPURLResponse *httpResponse = (NSHTTPURLResponse *)response;
        responseString = [NSString stringWithFormat:@"Received HTTP Response: Status %d",
                          [httpResponse statusCode]];
    }

    // if we can't utf8-decode the data, we'll just show the raw 'description' of
    // the NSData object...
    NSString *receivedString = [[[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding] autorelease];
    id dataDescription = receivedString ? receivedString : [data description];
    
    self.resultView.text = [NSString stringWithFormat:@"%@\n\nData: %@", responseString, dataDescription];
}

@end

#pragma mark - Custom URLConnectionDelegate implementation
@implementation MyConnectionDelegate
- (id)initWithController:(CertVerifyDemoViewController *)controller_in
{
    if ((self = [super init])) {
        controller = controller_in;
        receivedData = nil;
        response = nil;
    }
    return self;
}
- (void)dealloc
{
    [receivedData release];
    [response release];
    [super dealloc];
}

- (void)connection:(NSURLConnection *)connection didFailWithError:(NSError *)error
{
    [controller connectionFailed:error];
}

- (void)connection:(NSURLConnection *)connection didReceiveResponse:(NSURLResponse *)response_in
{
    response = [response_in retain];
    receivedData = [[NSMutableData alloc] init];
}

- (void)connection:(NSURLConnection *)connection didReceiveData:(NSData *)data
{
    [receivedData appendData:data];
}

- (void)connectionDidFinishLoading:(NSURLConnection *)connection
{
    [controller connectionDoneWithResponse:response data:receivedData];
}
@end