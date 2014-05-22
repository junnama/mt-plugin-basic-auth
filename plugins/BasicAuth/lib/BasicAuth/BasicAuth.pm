package BasicAuth::BasicAuth;

use strict;
use MIME::Base64();

sub _auth {
    my $app = MT->instance();
    if ( ref( $app ) =~ /^MT::App/ ) {
        return 1 if $_[0]->name eq 'init_app';
    }
    return 1 if ( ref $app ) ne 'MT::App::CMS';
    my $cache = MT->request( 'plugin-basicauth-init' );
    return 1 if $cache;
    MT->request( 'plugin-basicauth-init', 1 );
    my $authrized;
    my $component = MT->component( 'BasicAuth' );
    my $auth_username = $component->get_config_value( 'auth_username' );
    my $auth_password = $component->get_config_value( 'auth_password' );
    if ( $app->config( 'EnableBasicAuth' ) ) {
        if ( $auth_username && $auth_password ) {
            if ( my $auth = $app->get_header( 'AUTHORIZATION' ) ) {
                my @auths = split( /\s/, $auth );
                $auth = $auths[ 1 ];
                $auth = MIME::Base64::decode_base64( $auth );
                @auths = split( /:/, $auth );
                if ( scalar( @auths ) == 2 ) {
                    my $username = $auths[ 0 ];
                    my $password = $auths[ 1 ];
                    if ( ( $username eq $auth_username ) &&
                        ( $password eq $auth_password ) ) {
                        $authrized = 1;
                    }
                }
            }
            if (! $authrized ) {
                $app->logout();
                $app->delete_param( 'username' );
                $app->delete_param( 'password' );
                $app->user( undef );
                $app->response_code( '401' );
                $app->set_header( 'WWW-Authenticate', 'Basic realm="Please enter your ID and Password"' );
            }
        }
    }
}

1;