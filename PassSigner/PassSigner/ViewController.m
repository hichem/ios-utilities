//
//  ViewController.m
//  PassSigner
//
//  Created by Hichem BOUSSETTA on 21/01/13.
//  Copyright (c) 2013 Hichem BOUSSETTA. All rights reserved.
//

#import "ViewController.h"

@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad
{
    [super viewDidLoad];
	// Do any additional setup after loading the view, typically from a nib.
    
    [self signPass];
}

- (void)didReceiveMemoryWarning
{
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}



-(void)signPass {
    NSLog(@"%s", __FUNCTION__);
    
    NSString * documentDirectory = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) objectAtIndex:0];
    NSString * passPackagePath = [documentDirectory stringByAppendingPathComponent:@"PreorderPass.raw"];
    NSString * passPath = [documentDirectory stringByAppendingPathComponent:@"PreorderPass.pkpass"];
    
    NSFileManager * fileManager = [NSFileManager defaultManager];
    
    if ([fileManager fileExistsAtPath:passPath]) {
        
        //Remove existing pass
        [fileManager removeItemAtPath:passPath error:nil];
    }
    
    if ([fileManager fileExistsAtPath:passPackagePath]) {
        
        //Remove existing pass folder
        [fileManager removeItemAtPath:passPackagePath error:nil];
    }
    
    //Create new pass folder
    [fileManager createDirectoryAtPath:passPackagePath withIntermediateDirectories:nil attributes:nil error:nil];
    
    //Copy the pass files to the pass folder
    [[NSData dataWithContentsOfFile:[[NSBundle mainBundle] pathForResource:@"icon" ofType:@"png"]] writeToFile:[passPackagePath stringByAppendingPathComponent:@"icon.png"] options:0 error:nil];
    [[NSData dataWithContentsOfFile:[[NSBundle mainBundle] pathForResource:@"icon@2x" ofType:@"png"]] writeToFile:[passPackagePath stringByAppendingPathComponent:@"icon@2x.png"] options:0 error:nil];
    [[NSData dataWithContentsOfFile:[[NSBundle mainBundle] pathForResource:@"logo" ofType:@"png"]] writeToFile:[passPackagePath stringByAppendingPathComponent:@"logo.png"] options:0 error:nil];
    [[NSData dataWithContentsOfFile:[[NSBundle mainBundle] pathForResource:@"logo@2x" ofType:@"png"]] writeToFile:[passPackagePath stringByAppendingPathComponent:@"logo@2x.png"] options:0 error:nil];
    [[NSData dataWithContentsOfFile:[[NSBundle mainBundle] pathForResource:@"pass" ofType:@"json"]] writeToFile:[passPackagePath stringByAppendingPathComponent:@"pass.json"] options:0 error:nil];
    
    NSString * signingCertificate = [[NSBundle mainBundle] pathForResource:@"SigningCert" ofType:@"p12"];
    NSString * caCertificate = [[NSBundle mainBundle] pathForResource:@"AppleWWDRCA" ofType:@"cer"];
    
    [PassSigner signPassWithURL:[NSURL fileURLWithPath:passPackagePath] certPath:signingCertificate caCertPath:caCertificate outputURL:[NSURL fileURLWithPath:passPath] zip:YES];
}

@end
