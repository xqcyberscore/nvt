###############################################################################
# OpenVAS Vulnerability Test
# $Id: sw_ssl_cert_get_hostname.nasl 10425 2018-07-05 14:11:33Z cfischer $
#
# SSL/TLS: Hostname discovery from server certificate
#
# Authors:
# Christian Fischer <info@schutzwerk.com>
#
# Copyright:
# Copyright (c) 2015 SCHUTZWERK GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.111010");
  script_version("$Revision: 10425 $");
  script_tag(name:"last_modification", value:"$Date: 2018-07-05 16:11:33 +0200 (Thu, 05 Jul 2018) $");
  script_tag(name:"creation_date", value:"2015-03-27 12:00:00 +0100 (Fri, 27 Mar 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("SSL/TLS: Hostname discovery from server certificate");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2015 SCHUTZWERK GmbH");
  script_family("SSL and TLS");
  script_dependencies("ssl_cert_details.nasl");
  script_mandatory_keys("ssl/cert/avail");

  script_tag(name:"summary", value:"It was possible to discover an additional hostname
  of this server from its certificate Common or Subject Alt Name.");

  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("misc_func.inc");
include("host_details.inc");

if( ! find_in_path( "ping" ) ) exit( 0 );

hostname             = get_host_name();
hostip               = get_host_ip();
resolvableFound      = FALSE;
resolvableOtherFound = FALSE;
additionalFound      = FALSE;
report               = "";
resolvableHostnames  = make_list();
resolvableOther      = make_list();
additionalHostnames  = make_list();
ping_args            = make_list();
i                    = 0;
ipv4pattern          = "([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})";

# https://stackoverflow.com/a/17871737
ipv6pattern = "(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))";

# nb: There are differences between inetutils and iputils packages and versions.
# Some packages have e.g. a ping6 binary, others just a symlink from ping6 to ping.
#
# First check if the ping command supports the -6/-4 parameter
check = pread( cmd:"ping", argv:make_list( "--usage" ), cd:1 );
if( "Usage: ping" >< check && "64]" >< check ) {
  param64 = TRUE;
}

if( TARGET_IS_IPV6() ) {
  # If the -6 parameter is available explicitly specify it for the ping command and use only "ping"
  if( param64 ) {
    ping_cmd       = "ping";
    ping_args[i++] = "-6";
  } else {
    if( find_in_path( "ping6" ) ) {
      ping_cmd = "ping6";
    } else {
      ping_cmd = "ping";
    }
  }
  pattern = ipv6pattern;
} else {
  # If the -4 parameter is available explicitly specify it for the ping command
  if( param64 ) {
    ping_cmd       = "ping";
    ping_args[i++] = "-4";
  } else {
    ping_cmd = "ping";
  }
  pattern = ipv4pattern;
}

# nb: Only use one ping and a low timeout of one second (default is 10) so we don't
# waste too much time here as we only want the hostname resolved by the ping command
# nb: All three parameters are available in ping of inetutils and iputils
ping_args[i++] = "-c 1";
ping_args[i++] = "-W 1";
ping_args[i++] = "-w 2";

tmpHostnames = get_kb_list( "HostDetails/Cert/*/hostnames" );

if ( ! isnull( tmpHostnames ) ) {

  foreach certHostnames( keys( tmpHostnames ) ) {

    hostnames = get_kb_item( certHostnames  );

    foreach tmpHostname( split( hostnames, sep:",", keep:FALSE ) ) {

      # Basic sanity check
      if( ! strlen( tmpHostname ) > 0 || " " >< tmpHostname ) continue;

      # Don't ping known host, wildcard cert or localhost/localdomain hostnames
      if( hostname == tmpHostname || "*." >< tmpHostname || tmpHostname == "localhost" || tmpHostname == "localdomain" ) continue;

      # Same goes for IP addresses within the CN/SAN
      if( eregmatch( pattern:ipv4pattern, string:tmpHostname ) || eregmatch( pattern:ipv6pattern, string:tmpHostname ) ) continue;

      cnIp     = pread( cmd:ping_cmd, argv:make_list( ping_args , tmpHostname ), cd:1 );
      cnIpPing = eregmatch( pattern:pattern, string:cnIp );

      if( cnIpPing ) {
        if( hostip == cnIpPing[0] ) {
          if( ! in_array( search:tmpHostname, array:resolvableHostnames ) ) {
            resolvableFound     = TRUE;
            resolvableHostnames = make_list( resolvableHostnames, tmpHostname );
          }
        } else {
          if( ! in_array( search:tmpHostname, array:resolvableOther ) ) {
            resolvableOtherFound = TRUE;
            resolvableOther      = make_list( resolvableOther, tmpHostname );
          }
        }
      } else {
        if( ! in_array( search:tmpHostname, array:additionalHostnames ) ) {
          additionalFound     = TRUE;
          additionalHostnames = make_list( additionalHostnames, tmpHostname );
        }
      }
    }
  }
}

if( resolvableFound ) {

  report += 'The following additional and resolvable hostnames were detected:\n\n';

  # Sort to not report changes on delta reports if just the order is different
  resolvableHostnames = sort( resolvableHostnames );

  foreach tmp( resolvableHostnames ) {
    set_kb_item( name:"DNS_via_SSL_TLS_Cert", value:tmp );
    register_host_detail( name:"DNS-via-SSL-TLS-Cert", value:tmp, desc:"SSL/TLS: Hostname discovery from server certificate" );
    report += tmp + '\n';

    # Available since GVM-10 / git commit cf2ed60
    if( defined_func( "add_host_name" ) )
      add_host_name( hostname:tmp, source:"SSL/TLS server certificate" );

  }
  report += '\n';
}

if( resolvableOtherFound ) {

  report += 'The following additional and resolvable hostnames pointing to a different host ip were detected:\n\n';

  # Sort to not report changes on delta reports if just the order is different
  resolvableOther = sort( resolvableOther );

  foreach tmp( resolvableOther ) {
    report += tmp + '\n';
  }
  report += '\n';
}

if( additionalFound ) {

  report += 'The following additional but not resolvable hostnames were detected:\n\n';

  # Sort to not report changes on delta reports if just the order is different
  additionalHostnames = sort( additionalHostnames );

  foreach tmp( additionalHostnames ) {
    report += tmp + '\n';
  }
  report += '\n';
}

if( resolvableFound || additionalFound || resolvableOtherFound ) {
  log_message( port:0, data:report );
}

exit( 0 );
