#!/usr/bin/env perl
use strict;

our $VERSION = "0.01";

use constant LDAP_SERVER    => "ldap.db.scl3.mozilla.com";
use constant BIND_USER      => "uid=bind-labs,ou=logins,dc=mozilla";
use constant BIND_PASSWORD  => "XXX";

#XXX: This needs to be dynamic/renewed
use constant ADMIN_TOKEN    => "XXX";
use constant ADMIN_USER     => "vcap-proxy-auth";
use constant ADMIN_PASSWORD => "sekrit";

use CGI;
use CGI::Carp;
use URI::Escape::XS qw(uri_unescape);
use Data::Dumper;
use JSON;
use Net::LDAP;

use LWP::UserAgent;
my $ua = LWP::UserAgent->new(
    'agent' => "CF-Proxy-Auth/v$VERSION",
);

my $q = CGI->new();

my $data = decode_json($q->param('POSTDATA'));
my $url = uri_unescape($q->url(-absolute=>1));

( my $email = $url ) =~ s[/users/(.*)/tokens/?][$1];
my $password = $data->{password};

if (not login_ldap($email, $password)) {
    error(401, "Failed LDAP login for $email");
}

if (not exist_cf_user($email)) {
    warn "Need to create cloud foundry user for $email";
    create_cf_user($email);
}
else { warn "Already known account"; }

get_cf_token($email);

sub error {
    my ($status, $msg) = @_;
    
    carp $msg;
    
    print $q->header(
        -type => 'text/plain',
        -status => $status,
    );
    print $msg;
    exit; 
}

sub login_ldap {
    my ($email, $password) = @_;
    
    warn "Login attempt from $email/XXXXX";
    
    my $ldap = Net::LDAP->new(LDAP_SERVER);
    $ldap->bind(BIND_USER,
        password => BIND_PASSWORD,
    );

    my $res = $ldap->search(
        base    => "dc=mozilla",
        filter  =>  "mail=$email",
    );

    $res->code && warn $res->error;

    my $n = $res->count();
    if ($n == 0) {
        error(404, "User $email not found");
    }
    elsif ($n > 1) {
        error(500, "Found multiple LDAP accounts for $email ?!?!");  
    }

    my $entry = $res->entry(0);
    my $dn = $entry->dn();

    warn "Found dn='$dn' for $email";

    my $login = $ldap->bind($dn,
        password => $password);

    my $code = $login->code;
    
    if ($login->is_error) {
        error(401, "Failed LDAP login " . $login->error);
    }
    
    warn "User $email logged into LDAP ok";
    
    return 1;
}
 
sub exist_cf_user {
    my $email = shift;
    
    my $req = HTTP::Request->new(GET => "https://api.vcap.mozillalabs.com/users/$email");
    $req->header("Authorization" => ADMIN_TOKEN);

    my $res = $ua->request($req);
    
    return $res->is_success;
}

sub create_cf_user {
    my $email = shift;
    
    my $req = HTTP::Request->new(POST => "https://api.vcap.mozillalabs.com/users");
    $req->header("Authorization" => ADMIN_TOKEN);
    $req->header("Content-type" => "application/json");
    my $content = encode_json({
        'email' => $email,
        'password' => 'sekrit'
    });
    
    $req->content($content);
    my $res = $ua->request($req);
    
    if (!$res->is_success) {
        error(401, "Cloudfoundry account creation failed " . $res->status_line);
    }
    
    return 1;
}

sub get_cf_token {
    my $email = shift;

    my $req = HTTP::Request->new(POST => "https://api.vcap.mozillalabs.com/users/$email/tokens");
    $req->header("Authorization" => ADMIN_TOKEN);
    $req->header("Content-type" => "application/json");
    $req->content("{}");
    
    my $res = $ua->request($req);
    
    if (!$res->is_success) {
        error(401, "Cloudfoundry login failed " . $res->status_line);
    }
    
    my $content = $res->decoded_content;
    my $content_type = $res->header("Content-type");
    print $q->header(
        -type => $content_type,  
    );
    print $content;
    
    return 1;
}
