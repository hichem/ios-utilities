/*
 <codex><abstract>signpass</abstract></codex>
 */

#import "PassSigner.h"
#import <CommonCrypto/CommonDigest.h>
#import <Security/Security.h>

#define PASS_IDENTITY_PREFIX @"Pass Type ID: "


#include <stdio.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/pkcs7.h>
#include <openssl/err.h>


void PSPrintLine(NSString *format, ...) {
    va_list args;
    va_start(args, format);
    NSString *string = [[NSString alloc] initWithFormat:format arguments:args];
    va_end(args);
    fprintf(stdout, "%s\n", [string UTF8String]);
    [string release];
}



@interface NSData(SHA1Hashing)
- (NSString *)SHA1HashString;
@end

@implementation NSData(SHA1Hashing)

// Returns the SHA1 hash of a data as a string
- (NSString *)SHA1HashString {
    
    // Generate the hash.
    unsigned char sha1[CC_SHA1_DIGEST_LENGTH];
    if(!CC_SHA1([self bytes], (CC_LONG)[self length], sha1)) {
        return nil;
    }
    
    // Append the bytes in the correct format.
    NSMutableString * hashedResult = [[NSMutableString alloc] init];
    for (unsigned i = 0; i < CC_SHA1_DIGEST_LENGTH; i++) {
        [hashedResult appendFormat:@"%02x", sha1[i]];    
    }
    return [hashedResult autorelease];
}

@end

@implementation PassSigner


+(void)signPassWithURL:(NSURL *)passURL certPath:(NSString*)certPath caCertPath:(NSString *)caCertPath outputURL:(NSURL *)outputURL zip:(BOOL)zip {
        
    // Dictionary to store our manifest hashes
    NSMutableDictionary *manifestDictionary = [[NSMutableDictionary alloc] init];
    
    // Temporary files
    NSFileManager *defaultManager = [NSFileManager defaultManager];
    NSString *temporaryPath = [passURL path];
    NSURL *tempURL = [NSURL fileURLWithPath:temporaryPath];
    
    
    // Build an enumerator to go through each file in the pass directory
    NSDirectoryEnumerator *enumerator = [defaultManager enumeratorAtURL:tempURL includingPropertiesForKeys:nil options:0 errorHandler:nil];
    
    // For each file in the pass directory...
    for (NSURL *theURL in enumerator) {
        NSNumber *isRegularFileNum = nil;
        NSError *error = nil;
        
        // Don't allow oddities like symbolic links
        if (![theURL getResourceValue:&isRegularFileNum forKey:NSURLIsRegularFileKey error:&error] || ![isRegularFileNum boolValue]) {
            if (error) {
                NSLog(@"error: %@", [error localizedDescription]);
            }
            continue;
        }
        
        // Build a hash of the data.
        NSData *fileData = [NSData dataWithContentsOfURL:theURL];
        NSString *sha1Hash = [fileData SHA1HashString];
        
        // Build a key, relative to the root of the directory
        NSArray *basePathComponents = [tempURL pathComponents];
        NSArray *urlPathComponents = [theURL pathComponents];
        
        NSRange range;
        range.location = ([basePathComponents count] + 1);
        range.length = [urlPathComponents count] - ([basePathComponents count] + 1);
        NSArray *relativePathComponents = [urlPathComponents subarrayWithRange:range];
        
        NSString *relativePath = [NSString pathWithComponents:relativePathComponents];
        
        if (relativePath) {
            // Store the computed hash and key
            [manifestDictionary setObject:sha1Hash forKey:relativePath];
        }
    }
    
    // Write out the manifest dictionary
    NSURL *manifestURL = [tempURL URLByAppendingPathComponent:@"manifest.json"];
    NSData *jsonData = [NSJSONSerialization dataWithJSONObject:manifestDictionary options:NSJSONWritingPrettyPrinted error:nil];
    [jsonData writeToURL:manifestURL atomically:YES];
    NSLog (@"%@", manifestDictionary);
    [manifestDictionary release];
    
    if([self signManifest:jsonData toPath:[temporaryPath stringByAppendingPathComponent:@"signature"] withPKCS12FilePath:certPath andAdditionalCACertPath:caCertPath]) {
        NSLog(@"%s Signature saved at %@", __FUNCTION__, [temporaryPath stringByAppendingPathComponent:@"signature"]);
    }
    
    
    //Zip if necessary
    if (zip) {
        ZipArchive * zipper = [[ZipArchive alloc] init];
        zipper.delegate = [Logger sharedLogger];
        [zipper CreateZipFile2:[outputURL path]];
        
        NSDirectoryEnumerator *enumerator = [defaultManager enumeratorAtURL:tempURL includingPropertiesForKeys:nil options:0 errorHandler:nil];
        
        // For each file in the pass directory...
        for (NSURL *theURL in enumerator) {
            [zipper addFileToZip:[theURL path] newname:[theURL lastPathComponent]];
        }
        
        [zipper CloseZipFile2];
        [zipper release];
    }
}


/*
+ (void)verifyPassSignatureWithURL:(NSURL *)passURL {
    
    if (passURL) {
        // get a temporary place to unpack the pass
        NSString *temporaryDirectory = NSTemporaryDirectory();
        NSString *temporaryPath = [temporaryDirectory stringByAppendingPathComponent:[passURL lastPathComponent]];
        NSURL *tempURL = [NSURL fileURLWithPath:temporaryPath];
        
        // unzip the pass there
        NSTask *unzipTask = [[NSTask alloc] init];
        [unzipTask setLaunchPath:@"/usr/bin/unzip"];
        NSArray *argsArray = [NSArray arrayWithObjects:@"-q", @"-o", [passURL path], @"-d", [tempURL path], nil];
        [unzipTask setArguments:argsArray];
        [unzipTask launch];
        [unzipTask waitUntilExit];
        [unzipTask release];
        
        if ([unzipTask terminationStatus] == 0) {
            
            BOOL valid = [self validateManifestAtURL:tempURL] && [self validateSignatureAtURL:tempURL];
            if (valid) {
                PSPrintLine(@"\n*** SUCCEEDED ***");
            } else {
                PSPrintLine(@"\n*** FAILED ***");
            }
        }
    }
}

+ (BOOL)validateSignatureAtURL:(NSURL *)tempURL {
    BOOL valid = NO;
    
    // pick up the manifest and signature
    NSURL *signatureURL = [tempURL URLByAppendingPathComponent:@"signature"];
    NSURL *manifestURL = [tempURL URLByAppendingPathComponent:@"manifest.json"];
    NSData *signature = [NSData dataWithContentsOfURL:signatureURL];
    NSData *manifest = [NSData dataWithContentsOfURL:manifestURL];
    
    // set up a cms decoder
    CMSDecoderRef decoder;
    CMSDecoderCreate(&decoder);
    CMSDecoderSetDetachedContent(decoder, (CFDataRef)manifest);
    CMSDecoderUpdateMessage(decoder, [signature bytes], [signature length]);
    CMSDecoderFinalizeMessage(decoder);
    
    CMSSignerStatus status;
    OSStatus result;
    
    SecPolicyRef policy = SecPolicyCreateBasicX509();
    SecTrustRef trust;
    
    // obtain the status
    CMSDecoderCopySignerStatus(decoder, 0, policy, NO, &status, &trust, &result);
    
    if (kCMSSignerValid == status) {
        PSPrintLine(@"Signature valid.");
        
        // validate trust chain
        SecTrustResultType trustResult;
        SecTrustEvaluate(trust, &trustResult);
        
        if (kSecTrustResultUnspecified == trustResult) {
            CFArrayRef certs;
            CMSDecoderCopyAllCerts(decoder, &certs);
            
            BOOL foundWWDRCert = NO;

            if (CFArrayGetCount(certs) > 0) {
                PSPrintLine(@"Certificates: (");
                for (CFIndex i=0; i < CFArrayGetCount(certs); i++) {
                    SecCertificateRef cert = (SecCertificateRef)CFArrayGetValueAtIndex(certs, i);
                    CFStringRef commonName = NULL;
                    SecCertificateCopyCommonName(cert, &commonName);
                    PSPrintLine(@"\t%ld: %@", i, commonName);
                    
                    // one of the certs needs to be the WWDR one
                    if (!CFStringCompare(commonName, CFSTR("Apple Worldwide Developer Relations Certification Authority"), 0)) {
                        foundWWDRCert = YES;
                    }
                    if (commonName) {
                        CFRelease(commonName);
                    }
                }
                PSPrintLine(@")");
            }
            
            if (certs) {
                CFRelease(certs);
            }
            
            if (foundWWDRCert) {
                PSPrintLine(@"Trust chain is valid.");
                valid = YES;
            } else {
                PSPrintLine(@"The Apple WWDR Intermediate Certificate must be included in the signature.\nhttps://developer.apple.com/certificationauthority/AppleWWDRCA.cer");
            }
            
        } else {
            // trust chain wasn't verified
            CFArrayRef propertiesArray = SecTrustCopyProperties(trust);
            PSPrintLine(@"Error validating trust chain:");
            for (CFIndex i=0; i < CFArrayGetCount(propertiesArray); i++) {
                CFDictionaryRef properties = CFArrayGetValueAtIndex(propertiesArray, i);
                CFStringRef title = CFDictionaryGetValue((CFDictionaryRef)properties, kSecPropertyTypeTitle);
                CFStringRef error = CFDictionaryGetValue((CFDictionaryRef)properties, kSecPropertyTypeError);
                PSPrintLine(@"\t%@: %@", (NSString *)title, (NSString *)error);
            }
            if (propertiesArray) {
                CFRelease(propertiesArray);
            }
        }
        
        if (trust) CFRelease(trust);
        
    } else {
        // signature wasn't valid
        CFStringRef errorString = SecCopyErrorMessageString(result, NULL);
        PSPrintLine(@"Error validating signature: %@", errorString);
        if (errorString) {
            CFRelease(errorString);
        }
    }
    
    if (decoder) {
        CFRelease(decoder);
    }

    return valid;
}

+ (BOOL)validateManifestAtURL:(NSURL *)passURL {
    BOOL valid = YES;
    
    NSURL *manifestURL = [passURL URLByAppendingPathComponent:@"manifest.json"];
    NSData *manifestData = [NSData dataWithContentsOfURL:manifestURL];
    NSError *error = NULL;
    NSMutableDictionary *manifest = [[NSJSONSerialization JSONObjectWithData:manifestData options:0 error:&error] mutableCopy];
    if (manifest) {
        NSFileManager *defaultManager = [NSFileManager defaultManager];
        
        NSDirectoryEnumerator *enumerator = [defaultManager enumeratorAtURL:passURL
                                                 includingPropertiesForKeys:@[ NSURLFileSizeKey, NSURLIsDirectoryKey ]
                                                                    options:0
                                                               errorHandler:nil];
        
        for (NSURL *theURL in enumerator) {
            NSNumber *isDirectoryNum = nil;
            if ([theURL getResourceValue:&isDirectoryNum forKey:NSURLIsDirectoryKey error:NULL] && [isDirectoryNum boolValue]) {
                continue;
            }
            
            NSArray *basePathComponents = [[passURL URLByResolvingSymlinksInPath] pathComponents];
            NSArray *urlPathComponents = [[theURL URLByResolvingSymlinksInPath] pathComponents];
            
            NSRange range;
            range.location = ([basePathComponents count]);
            range.length = [urlPathComponents count] - ([basePathComponents count]);
            NSArray *relativePathComponents = [urlPathComponents subarrayWithRange:range];
            
            NSString *relativePath = [NSString pathWithComponents:relativePathComponents];
            
            //ignore the signature and manifest files
            if (![relativePath isEqualToString:@"manifest.json"] &&
                ![relativePath isEqualToString:@"signature"]) {
                
                NSString *manifestSHA1 = [manifest objectForKey:relativePath];
                if (!manifestSHA1) {
                    PSPrintLine(@"No entry in manifest for file %@", relativePath);
                    valid = NO;
                    break;
                }
                
                NSData *fileData = [[NSData alloc] initWithContentsOfURL:theURL];
                NSString *hexSHA1 = [fileData SHA1HashString];
                
                if (![hexSHA1 isEqualToString:manifestSHA1]) {
                    PSPrintLine(@"For file %@, manifest's listed SHA1 hash %@ doesn't match computed hash, %@", relativePath, manifestSHA1, hexSHA1);
                    [fileData release];
                    valid = NO;
                    break;
                }
                
                if (relativePath) {
                    [manifest removeObjectForKey:relativePath];
                }
                [fileData release];
            }
            
            BOOL isSymLink = [[[defaultManager attributesOfItemAtPath:[passURL absoluteString] error:nil] objectForKey:NSFileType] isEqualToString:NSFileTypeSymbolicLink];
            
            if (isSymLink) {
                PSPrintLine(@"Card contains a symlink, %@, which is illegal", relativePath);
                break;
                valid = NO;
            }
        }
        
        if (valid && [manifest count]) {
            PSPrintLine(@"Card is missing files listed in the manifest, %@", manifest);
            valid = NO;
        }
    } else {
        PSPrintLine(@"Manifest didn't parse. %@", [error localizedDescription]);
    }
    
    [manifest release];
    
    return valid;
}
*/



+(BOOL)signManifest:(NSData *)manifest toPath:(NSString *)signaturePath withPKCS12FilePath:(NSString *)pkcs12 andAdditionalCACertPath:(NSString *)intermediateCertPath {
    NSLog(@"%s", __FUNCTION__);
    
    BOOL result = NO;
    
    FILE *fp;
    BIO *in = NULL, *out = NULL;
    PKCS12 *p12;
	X509 *scert = NULL, *caCert = NULL;
    STACK_OF(X509) *ca = NULL;
	EVP_PKEY *skey = NULL;
	PKCS7 *p7 = NULL;
    
	/* For simple S/MIME signing use PKCS7_DETACHED.
	 * On OpenSSL 0.9.9 only:
	 * for streaming detached set PKCS7_DETACHED|PKCS7_STREAM
	 * for streaming non-detached set PKCS7_STREAM
	 */
	int flags = PKCS7_DETACHED | PKCS7_BINARY;
    
	OpenSSL_add_all_algorithms();
	ERR_load_crypto_strings();
    
    
	/* Read in signer certificate and private key */
    
    if (!(fp = fopen([pkcs12 UTF8String], "rb"))) {
		NSLog(@"%s Error opening file %@", __FUNCTION__, pkcs12);
        goto end;
    }
    
    p12 = d2i_PKCS12_fp(fp, NULL);
    fclose (fp);
    if (!p12) {
        NSLog(@"%s Error reading PKCS#12 file", __FUNCTION__);
        ERR_print_errors_fp(stderr);
        goto end;
    }
    
    if (!PKCS12_parse(p12, "", &skey, &scert, &ca)) {
        NSLog(@"%s Error parsing PKCS#12 file", __FUNCTION__);
        ERR_print_errors_fp(stderr);
        goto end;
    }
    
    PKCS12_free(p12);
    
	if (!scert || !skey)
		goto end;
    
    
    /* Read intermediate */
    
    if (!(fp = fopen([intermediateCertPath UTF8String], "rb"))) {
		NSLog(@"%s Error opening file %@", __FUNCTION__, intermediateCertPath);
        goto end;
    }
    
    caCert = d2i_X509_fp(fp, NULL);
    fclose (fp);
    if (!caCert) {
        NSLog(@"%s Error reading X509 Certificate file", __FUNCTION__);
        ERR_print_errors_fp(stderr);
        goto end;
    }
    
    if (ca == NULL) {
        ca = sk_X509_new_null();
    }
    
    sk_X509_push(ca, caCert);
    
	/* Open content being signed */
    
	in = BIO_new_mem_buf((void *)[manifest bytes], [manifest length]);
    
	if (!in)
		goto end;
    
	/* Sign content */
	p7 = PKCS7_sign(scert, skey, ca, in, flags);
    
	if (!p7)
		goto end;
    
	out = BIO_new_file([signaturePath UTF8String], "w");
	if (!out)
		goto end;
    
	//if (!(flags & PKCS7_STREAM))
	//	BIO_reset(in);
    
	/* Write out S/MIME message */
	//if (!SMIME_write_PKCS7(out, p7, in, flags))
    //if (!i2d_PKCS7_bio_stream(out, p7, in, flags))
    if (!i2d_PKCS7_bio(out, p7))
		goto end;
    
	result = YES;
    
end:
    
	if (result == NO)
    {
		NSLog(@"%s Error Signing Data", __FUNCTION__);
		ERR_print_errors_fp(stderr);
    }
    
    if (ca) {
        sk_X509_free(ca);
    }
    
	if (p7)
		PKCS7_free(p7);
	if (scert)
		X509_free(scert);
	if (skey)
		EVP_PKEY_free(skey);
    
	if (in)
		BIO_free(in);
	if (out)
		BIO_free(out);
    
    return result;
}

@end


static Logger * g_sharedLogger = nil;

@implementation Logger

+(Logger *)sharedLogger {
    if (g_sharedLogger == nil) {
        g_sharedLogger = [[Logger alloc] init];
    }
    return g_sharedLogger;
}

-(id)init {
    if ((self = [super init])) {
        
    }
    return self;
}

-(oneway void)release {
    
}

-(void)ErrorMessage:(NSString*)msg {
    NSLog(@"%s [%@]", __FUNCTION__, msg);
}

-(BOOL)OverWriteOperation:(NSString*)file {
    return YES;
}

@end
