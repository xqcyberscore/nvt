###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ssl_cert_soonexpired.nasl 7242 2017-09-23 14:58:39Z cfischer $
#
# SSL/TLS: Certificate Will Soon Expire
#
# Authors:
# Werner Koch <wk@gnupg.org>
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

# How many days in advance to warn of certificate expiry.
lookahead = 60;

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103957");
  script_version("$Revision: 7242 $");
  script_tag(name:"last_modification", value:"$Date: 2017-09-23 16:58:39 +0200 (Sat, 23 Sep 2017) $");
  script_tag(name:"creation_date", value:"2013-11-28 11:27:17 +0700 (Thu, 28 Nov 2013)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("SSL/TLS: Certificate Will Soon Expire");
  script_category(ACT_GATHER_INFO);
  script_family("SSL and TLS");
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("ssl_cert_details.nasl");
  script_mandatory_keys("ssl/cert/avail");

  script_tag(name:"insight", value:"This script checks expiry dates of certificates associated with
  SSL/TLS-enabled services on the target and reports whether any will expire during then next "
  + lookahead + " days.");

  script_tag(name:"solution", value:"Prepare to replace the SSL/TLS certificate by a new one.");

  script_tag(name:"summary", value:"The remote server's SSL/TLS certificate will soon expire.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("ssl_funcs.inc");
include("byte_func.inc");

# The current time
now = isotime_now();
if( strlen( now ) <= 0 ) exit( 0 ); # isotime_now: "If the current time is not available an empty string is returned."

# The current time plus lookahead
future = isotime_add( now, days:lookahead );
if( isnull( future ) ) exit( 0 ); # isotime_add: "or NULL if the provided ISO time string is not valid or the result would overflow (i.e. year > 9999).

# List of keys which expires soon
toexpire_keys = make_array();

ssls = get_kb_list( "HostDetails/SSLInfo/*" );

if( ! isnull( ssls ) ) {

  check_for = "expire_soon";

  foreach key( keys( ssls ) ) {

    tmp = split( key, sep:"/", keep:FALSE );
    port = tmp[2];
    vhost = tmp[3];

    fprlist = get_kb_item( key );
    if( ! fprlist ) continue;

    itmp = split( fprlist, sep:",", keep:FALSE );
    ifpr = itmp[0];
    ikey = "HostDetails/Cert/" + ifpr + "/";

    issuer = get_kb_item( ikey + "issuer" );

    # TODO: This will overwrite the previous declared "future" if there is a LE cert on one port but another cert on another port
    if( "Let's Encrypt Authority" >< issuer ) { # https://letsencrypt.org/2015/11/09/why-90-days.html
      lookahead = 28;
      future = isotime_add( now, days:lookahead );
      if( isnull( future ) ) continue; # isotime_add: "or NULL if the provided ISO time string is not valid or the result would overflow (i.e. year > 9999).
    }

    result = check_cert_validity( fprlist:fprlist, port:port, vhost:vhost,
                                  check_for:check_for, now:now, timeframe:future );
    if( result ) {
      toexpire_keys[port] = result;
    }
  }

  foreach port( keys( toexpire_keys ) ) {
    report = "The certificate of the remote service will expire within the next " + lookahead;
    report += " days on " + isotime_print( get_kb_item( toexpire_keys[port] + "notAfter" ) ) + '.\n';
    report += cert_summary( key:toexpire_keys[port] );
    log_message( data:report, port:port );
  }

  exit( 0 );
}

exit( 99 );
