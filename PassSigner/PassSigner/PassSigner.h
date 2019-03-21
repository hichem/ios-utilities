/*
 <codex><abstract>signpass</abstract></codex>
 */

#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import "ZipArchive.h"


void PSPrintLine(NSString *format, ...);

@interface PassSigner : NSObject

+ (void)signPassWithURL:(NSURL *)passURL certPath:(NSString*)certPath caCertPath:(NSString *)caCertPath outputURL:(NSURL *)outputURL zip:(BOOL)zip;
+ (void)verifyPassSignatureWithURL:(NSURL *)passURL;

@end


@interface Logger : NSObject<ZipArchiveDelegate>

+(Logger *)sharedLogger;

@end
