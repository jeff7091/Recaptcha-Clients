//
//  Recaptcha.h
//  Print To My Phone
//
//  Created by Jeff Enderwick on 8/31/09.
//  Copyright 2009 __MyCompanyName__. All rights reserved.
//

#import <Cocoa/Cocoa.h>


@interface Recaptcha : NSObject {
	NSURLConnection *currentConnection;
	id delegate;
	NSString *urlPrefix;
	NSString *lastChallenge;
	NSURL *postURL;
	NSString *publicKey;
	NSMutableData *rxData;
	enum {STATE_IDLE, STATE_CHAL_WAIT, STATE_IMG_WAIT, STATE_POST_WAIT} state;
}
- (void)cancel;
- (id)initWithPublicKey:(NSString*)publicKey postURL:(NSURL*)url delegate:(id)delegate;
- (BOOL)fetchChallenge;
- (BOOL)postForm:(NSDictionary*)form withResponse:(NSString*)response;
@end
