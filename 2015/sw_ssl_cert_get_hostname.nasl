###############################################################################
# OpenVAS Vulnerability Test
# $Id: sw_ssl_cert_get_hostname.nasl 5180 2017-02-03 07:25:25Z cfi $
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
  script_version("$Revision: 5180 $");
  script_tag(name:"last_modification", value:"$Date: 2017-02-03 08:25:25 +0100 (Fri, 03 Feb 2017) $");
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

include("ssl_funcs.inc");
include("byte_func.inc");
include("misc_func.inc");

if( ! find_in_path( "ping" ) ) exit( 0 );

pattern =  "([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})";
hostname = get_host_name();
hostip = get_host_ip();
resolvableFound = FALSE;
resolvableOtherFound = FALSE;
additionalFound = FALSE;
report = "";
resolvableHostnames = make_list();
resolvableOther = make_list();
additionalHostnames = make_list();

tmpHostnames = get_kb_list( "HostDetails/Cert/*/hostnames" );

if ( ! isnull( tmpHostnames ) ) {

  foreach certHostnames( keys( tmpHostnames ) ) {

    hostnames = get_kb_item( certHostnames  );

    foreach tmpHostname( split( hostnames, sep:",", keep:FALSE ) ) {

      # Don't ping known host or wildcard cert hostnames
      if( hostname == tmpHostname || "*." >< tmpHostname ) continue;

      cnIp = pread( cmd:"ping", argv:make_list( "ping", "-c 1", tmpHostname ), cd:1 );
      cnIpPing = eregmatch( pattern:pattern, string:cnIp );

      if( cnIpPing ) {
        if( hostip == cnIpPing[0] ) {
          if( ! in_array( search:tmpHostname, array:resolvableHostnames ) ) {
            resolvableFound = TRUE;
            resolvableHostnames = make_list( resolvableHostnames, tmpHostname );
          }
        } else {
          if( ! in_array( search:tmpHostname, array:resolvableOther ) ) {
            resolvableOtherFound = TRUE;
            resolvableOther = make_list( resolvableOther, tmpHostname );
          }
        }
      } else {
        if( ! in_array( search:tmpHostname, array:additionalHostnames ) ) {
          additionalFound = TRUE;
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
    report += tmp + '\n';
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
