# This package is distributed under GNU public license.
# See file COPYING for details.
# This is beta stage software. Use at your own risk.

package Apache::AuthChecker;

use Apache::ModuleConfig();
use DynaLoader();
use Apache::Constants ':common';
use IPC::Shareable;
use IPC::SysV qw(IPC_RMID);
use vars qw(%DB);
use vars qw($VERSION);
use Symbol;
use strict;

$VERSION = '0.11';

if ($ENV{MOD_PERL}) {
    no strict;
    @ISA = qw(DynaLoader);
    __PACKAGE__->bootstrap($VERSION);
}

my $debug = 0;
my $ipc_key = 0x27071975;
my $bytes_per_record = 45;

sub handler {
    my ($r) = @_;
    my $res;
    my $sent_pw;
    my $rc;

    return undef unless defined($r);

    my ($res, $sent_pw) = $r->get_basic_auth_pw;
    return $res if $res != OK;
    my $user = $r->connection->user;
    my $remote_ip = $r->connection->remote_ip;
    my $ignore_this_request = 0;
    my $cur_time = time();

    my $passwd_file = $r->dir_config('AuthUserFile');
    my $max_failed_attempts = $r->dir_config('MaxFailedAttempts') || 10;
    my $time_to_expire = 3600;
    
    my ($failed_attempts, $last_access);
    
    unless (defined %DB) {
        #Init stuff here
        my $mem_size = 65535;
        if (my $cfg = Apache::ModuleConfig->get($r)) {
            $mem_size = $cfg->{AuthCheckerMemSize} 
                if ($cfg->{AuthCheckerMemSize});
        }
        
        $r->log_error("AuthChecker started pid: $$ tie memory $mem_size...")
            if ($debug);
        tie %DB, 'IPC::Shareable', $ipc_key, 
            { create => 1, mode => 0644, size => $mem_size};
        unless (defined %DB) {
            $r->log_error("AuthChecker is unable to tie shared memory.");
            exit(1);
        }
        $r->log_error("AuthChecker started successfully.")
            if ($debug);
    };
        
    tied(%DB)->shlock;

    if (my $cfg = Apache::ModuleConfig->get($r)) {
        $time_to_expire = $cfg->{AuthCheckerSecondsToExpire} 
            if ($cfg->{AuthCheckerMemSize});
    }

    #Expire old hash records
    if (!defined($DB{0})) {
        $DB{0} = $cur_time;
    } elsif (($cur_time-$time_to_expire) > $DB{0}) {
        
    
        foreach $rc (keys %DB) {
            my ($x, $last_access) = split(':', $DB{$rc});
            if (($cur_time-$time_to_expire) > $last_access) {
                delete $DB{$rc};
                $r->log_error("IP: $remote_ip expired.");
            }
        }
        $DB{0} = $cur_time;
    }
    
    if (defined($DB{$remote_ip})) {
        ($failed_attempts, $last_access) = 
            split(':', $DB{$remote_ip});
            
        $r->log_error("Stats IP: $remote_ip Attempts: $failed_attempts")
            if ($debug);
        
        if ($failed_attempts >= $max_failed_attempts) {
            $r->log_error("IP: $remote_ip is blocked. ".
                          "Auth attempts: $failed_attempts");
            $ignore_this_request = 1;
        }
    } else {
        $r->log_error("IP: $remote_ip not found in DB.")
            if ($debug);
    }
    tied(%DB)->shunlock;
    

    if (!$ignore_this_request) {

        $rc = open(P, $passwd_file);
        if (!$rc) {
            $r->note_basic_auth_failure;
            $r->log_reason("Can't open file", $passwd_file);
            return AUTH_REQUIRED;
        };

        my $i;
        while ($i = <P>) {
            chomp $i;
            next if ($i =~ /^#/);
            my ($user_name, $saved_pw) = split(':',$i);
            next if ($user ne $user_name);
        
            my $gpw = crypt($sent_pw,$saved_pw);
            $r->log_error("User: $user Saved pw: $saved_pw Get pw: $gpw")
                if ($debug);
        
            if ($saved_pw ne crypt($sent_pw,$saved_pw)) {
                last;
            } else {
                return OK;
            }
        }
        close(P);
    }
    
    if ($failed_attempts) {
        $failed_attempts++;
    } else {
        $failed_attempts=1;
    }    
    $last_access = time();
    
    
    # Yes, I know: another process probably modified this
    # data. The worst thing may happen is lost attempt(s) or expire,
    # but lock is held considerably less and overall stability
    # is better.
    my $val = "$failed_attempts:$last_access";
    tied(%DB)->shlock;
    $DB{$remote_ip} = $val;
    tied(%DB)->shunlock;

    $r->note_basic_auth_failure;
    $r->log_error("Authorization for $user IP: $remote_ip failed. Attempts: $failed_attempts");  

    if ($ignore_this_request) {    
      my $uri = $r->dir_config('RedirectURI') || "/";
      $r->internal_redirect_handler($uri);
      return OK;
   } else {
     return AUTH_REQUIRED;
   }
}

sub PerlAuthCheckerMaxUsers ($$$) {
    my ($cfg, $parms, $arg) = @_;
    $cfg->{AuthCheckerMemSize} = $arg * $bytes_per_record;

    clean_up();    
}

sub PerlSecondsToExpire ($$$) {
    my ($cfg, $parms, $arg) = @_;
    $cfg->{AuthCheckerSecondsToExpire} = $arg;
    
    clean_up();
}

sub clean_up {
    #Remove old locks and memory - if our ancestor died ungracefully.
    my $sid = semget ($ipc_key,0,0);
    my $shmid = shmget ($ipc_key,0,0);
    semctl($sid,0,IPC_RMID,0) if (defined $sid);
    shmctl($shmid,IPC_RMID,0) if (defined $shmid);
}


1;
__END__


=head1 NAME

Apache::AuthChecker - mod_perl based authentication module used to prevent brute force attacks via HTTP authorization.

=head1 README

Apache::AuthChecker - mod_perl based authentication module used to prevent
brute force attacks via HTTP authorization. It remembers IP addresses of any
user trying to authenticate for certain period of time. If user
runs out limit of failed attempts to authenticate - all his authentication
requests will be redirected to some URI (like this: /you_are_blocked.html).

Requirements: 

 1. Apache 1.3.x with mod_perl 1.2x enabled 
 2. IPC::Shareable perl module version 0.60 by BSUGARS. Probably it
    should work with other versions, but I did not test.

Installation:

 -from the directory where this file is located, type:
     perl Makefile.PL
     make && make test && make install
                                  

Apache configuration process:

 1. Add directives to httpd.conf below directives LoadModule and AddModule:
    PerlModule Apache::AuthChecker
    PerlAuthCheckerMaxUsers 1450           
    PerlSecondsToExpire     3600           

 Note: parameter PerlAuthCheckerMaxUsers affects amount of shared memory 
  allocated. Rule to estimate: every IP record eats 45 bytes. It means if you 
  set 1000 users - 45Kbytes of shared memory will be allocated. Default
  setting is 64KByte which gives us about 1450 records.
  Exact value depends on PerlSecondsToExpire parameter.
  !!! It does not store ALL logins info, ONLY FAILED ONES BY IP.
      I see no need to make it big.
  Max limit depends on your OS settings.
  
 PerlSecondsToExpire - how long will we store data about authentication 
  failures.
   

 2. Use .htaccess or <Directory> or <Location> mechanisms with the 
  following directives (default values):

    AuthName "My secret area"
    PerlAuthenHandler Apache::AuthChecker
    PerlSetVar      AuthUserFile /path/to/my/.htpasswd
    PerlSetVar      MaxFailedAttempts 10
    PerlSetVar      RedirectURI /
    require valid-user

 Parameters:

 AuthUserFile       - path to your passwords htpasswd-made file (REQUIRED).
 MaxFailedAttempts  - Maximum attempts we give user to mistype password 
                      (OPTIONAL, default - 8).
 RedirectURI        - URI (not URL!) to redirect attacker then he runs out 
                      attempts limit ((OPTIONAL, default - /). 
                      For example: /you_are_blocked.html



=head1 DESCRIPTION

Apache::AuthChecker - mod_perl based authentication module used to prevent
brute force attacks via HTTP authorization. It remembers IP addresses of any
user trying to authenticate for certain period of time. If user from this IP
runs out limit of failed attempts to authenticate - all his authentication
requests will be redirected to some URI (like this: /you_are_blocked.html).

=head1 PREREQUISITES

 1. Apache 1.3.x with mod_perl 1.2x enabled 
 2. IPC::Shareable perl module version 0.60 by BSUGARS. Probably it
    should work with other versions, but I did not test.

=head1 AUTHOR

Andre Yelistratov 
 E-mail: andre@sundale.net
 ICQ: 9138065

=cut
