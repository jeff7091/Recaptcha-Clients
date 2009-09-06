//
//  Recaptcha.m
//  Print To My Phone
//
//  Created by Jeff Enderwick on 8/31/09.
//  Copyright 2009 __MyCompanyName__. All rights reserved.
//

#import "Recaptcha.h"

@implementation Recaptcha

- (void)cancelConnection {
	[currentConnection cancel];
	[currentConnection release];
	currentConnection = nil;
}

- (void)cancel {
	// quiesce, cleanup all per-fetchChallenge state. leave lastChallenge alone, as it is needed for the eventual POST (if ever).
	if (currentConnection) {
		[self cancelConnection];
	}
	if (rxData) {
		[rxData release];
		rxData = nil;
	}
	state = STATE_IDLE;
}

- (NSString*)extractChallengeString {
	NSString *response = [[NSString alloc] initWithData:rxData encoding:NSUTF8StringEncoding];
	NSLog(@"Recaptcha: [%@]", response);
	// No RegEx in Cocoa - how pathetic. need to match "challenge : 'thisisthechallengestring' inside the Javascript.
	enum {RC_START, RC_C, RC_H, RC_A, RC_L1, RC_L2, RC_E1, RC_N, RC_G, RC_WS1, RC_WS2, RC_RECORD, RC_STOP} scanState = RC_START;
	char front, matches[] = "challenge";
	int idx, len = [response length], chalStart = 0, chalLen = -1;
	for (idx = 0; idx < len && RC_STOP != scanState; ++idx) {
		front = [response characterAtIndex:idx];
		switch (scanState) {
			case RC_START:
				if (matches[0] == front) {
					scanState = RC_START+1;
				}
				break;
			case RC_WS1:
				if (! isspace(front)) {
					scanState = (':' == front) ? RC_WS2 : RC_START;
				}
				break;
			case RC_WS2:
				if (! isspace(front)) {
					chalStart = idx + 1;
					scanState = ('\'' == front) ? RC_RECORD : RC_START;
				}
				break;
			case RC_RECORD:
				if ('\'' == front) {
					scanState = RC_STOP;
					chalLen = idx - chalStart;
				}
				break;
			default:
				// handle scanning of 'challenge' here
				if (RC_START < scanState && RC_WS1 > scanState) {
					if (matches[scanState - RC_START] == front) {
						++ scanState;
					} else {
						scanState = RC_START;
					}
				}
				break;
		}
	}
	if (0 < chalLen) {
		return [response substringWithRange:NSMakeRange(chalStart, chalLen)];
	}
	return nil;
}

- (BOOL)fetchChallenge {
	if (STATE_IDLE != state) {
		// cancel anything currently going on
		[self cancel];
	}
	// first, use the public key to get the challenge
	state = STATE_CHAL_WAIT;
	NSString *url = [NSString stringWithFormat:@"%@challenge?k=%@", urlPrefix, publicKey];
	NSURLRequest *getRequest = [[[NSURLRequest alloc] initWithURL:[NSURL URLWithString:url]] autorelease];
	currentConnection = [[NSURLConnection alloc] initWithRequest:getRequest delegate:self];
	rxData = [[NSMutableData alloc] init];
	if (currentConnection && rxData) {
		return YES;
	}
	[self cancel];
	NSLog(@"Recaptcha: could not alloc NSMutableData or NSURLConnection");
	return NO;
}

- (void)fetchChallenge2ndHalf {
	// second, use the challenge value to get the image
	NSString *url = [NSString stringWithFormat:@"%@image?c=%@", urlPrefix, lastChallenge];
	NSURLRequest *getRequest = [[[NSURLRequest alloc] initWithURL:[NSURL URLWithString:url]] autorelease];
	currentConnection = [[NSURLConnection alloc] initWithRequest:getRequest delegate:self];
	rxData = [[NSMutableData alloc] init];
	if (!currentConnection || !rxData) {
		[self cancel];
		[delegate performSelector:@selector(recaptchaError)];
		NSLog(@"Recaptcha: could not alloc NSMutableData or NSURLConnection");
	}
}

- (void)provideChallengeImage {
	state = STATE_IDLE;
	NSImage *img = [[[NSImage alloc] initWithData:rxData] autorelease];
	if (! img) {
		[delegate performSelector:@selector(recaptchaError)];
		NSLog(@"Recaptcha: could not alloc NSImage");
		return;
	}
	[delegate performSelector:@selector(recaptchaChallengeImage:) withObject:img];
}

- (id)initWithPublicKey:(NSString*)key postURL:(NSURL*)url delegate:receiver {
	if (self = [super init]) {
		state = STATE_IDLE;
		publicKey = [key retain];
		postURL = [url retain];
		delegate = [receiver retain];
		urlPrefix = @"http://api.recaptcha.net/";
	}		
	return self;
}

- (void)dealloc {
	[self cancel];
	if (urlPrefix) {
		[urlPrefix release];
		urlPrefix = nil;
	}
	if (postURL) {
		[postURL release];
		postURL = nil;
	}
	if (publicKey) {
		[publicKey release];
		publicKey = nil;
	}
	if (lastChallenge) {
		[lastChallenge release];
		lastChallenge = nil;
	}	
	[super dealloc];
}

- (BOOL)postForm:(NSDictionary*)form withResponse:(NSString*)response {
	// buid the POST arguments using the form values, and the recaptcha response
	NSEnumerator *iter = [form keyEnumerator];
	NSString *postArgs = [[[NSString alloc] init] autorelease];
	NSString *key;
	while ((key = [iter nextObject])) {
		NSString *value = [form objectForKey:key];
		postArgs = [postArgs stringByAppendingFormat:@"%@=%@&",
					[key stringByAddingPercentEscapesUsingEncoding:NSUTF8StringEncoding],
					[value stringByAddingPercentEscapesUsingEncoding:NSUTF8StringEncoding]];
	}
	postArgs = [postArgs stringByAppendingFormat:@"%@=%@&%@=%@", @"recaptcha_response_field",
				[response stringByAddingPercentEscapesUsingEncoding:NSUTF8StringEncoding], @"recaptcha_challenge_field",
				[lastChallenge stringByAddingPercentEscapesUsingEncoding:NSUTF8StringEncoding]];
	
	// send the POST...
	state = STATE_POST_WAIT;
	NSMutableURLRequest *postRequest = [[[NSMutableURLRequest alloc] initWithURL:postURL] autorelease];
	[postRequest setHTTPMethod:@"POST"];
	[postRequest setValue:[NSString stringWithFormat:@"%d", [postArgs length]] forHTTPHeaderField:@"Content-Length"];
	[postRequest setValue:@"application/x-www-form-urlencoded" forHTTPHeaderField:@"Content-Type"];
	[postRequest setHTTPBody:[postArgs dataUsingEncoding:NSASCIIStringEncoding]];
	currentConnection = [[NSURLConnection alloc] initWithRequest:postRequest delegate:self];
	rxData = [[NSMutableData alloc] init];
	if (currentConnection && rxData) {
		return YES;
	}
	[self cancel];
	NSLog(@"Recaptcha: could not alloc NSMutableData or NSURLConnection");
	return NO;
}

- (void)connectionDidFinishLoading:(NSURLConnection *)connection {
	NSString *result;
	[self cancelConnection];
	switch (state) {
		case STATE_CHAL_WAIT:
			// extract the challenge string, and kick off the image fetch
			state = STATE_IMG_WAIT;
			if (lastChallenge) {
				[lastChallenge release];
			}
			lastChallenge = [[self extractChallengeString] retain];
			if (! lastChallenge) {
				[delegate performSelector:@selector(recaptchaError)];
				NSLog(@"Recaptcha: could not extract challenge string");
				[self cancel];
			} else {
				[rxData release];
				rxData = nil;
				[self fetchChallenge2ndHalf];
			}
			break;
		case STATE_IMG_WAIT:
			// pass the image to the delegate
			[self provideChallengeImage];
			[self cancel];
			break;
		case STATE_POST_WAIT:
			// check for a successful indication "OK", or "user message from server"
			result = [[[NSString alloc] initWithData:rxData encoding:NSUTF8StringEncoding] autorelease];
			[rxData release];
			rxData = nil;
			if (NSOrderedSame == [result compare:@"OK"]) {
				[delegate performSelector:@selector(recaptchaPostSuccessful)];
			} else {
				[delegate performSelector:@selector(recaptchaPostFailure:) withObject:result];
			}
			[self cancel];
			break;
		case STATE_IDLE:
			NSLog(@"Recaptcha: got a connection indication in the idle state: internal error");
			break;
	}
}

- (void)connection:(NSURLConnection *)connection didFailWithError:(NSError *)error {
	[self cancel];
	[delegate performSelector:@selector(recaptchaError)];
	NSLog(@"Recaptcha: NSURLConnection failed: %@ %@", [error localizedDescription],
          [[error userInfo] objectForKey:NSErrorFailingURLStringKey]);
}

- (void)connection:(NSURLConnection *)connection didReceiveResponse:(NSURLResponse *)response {
	[rxData setLength:0];
}

- (void)connection:(NSURLConnection *)connection didReceiveData:(NSData *)data {
	[rxData appendData:data];
}
@end
