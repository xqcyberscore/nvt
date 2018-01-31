###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_portscanner_missing.nasl 8582 2018-01-30 12:20:37Z cfischer $
#
# Check for enabled / working Port scanner plugin
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (c) 2018 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108323");
  script_version("$Revision: 8582 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-30 13:20:37 +0100 (Tue, 30 Jan 2018) $");
  script_tag(name:"creation_date", value:"2018-01-30 11:21:18 +0100 (Tue, 30 Jan 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Check for enabled / working Port scanner plugin");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2018 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("toolcheck.nasl"); # For Tools/Present/nmap
  script_exclude_keys("Host/scanned"); # Set by the Port scanner plugins

  script_xref(name:"URL", value:"http://docs.greenbone.net/GSM-Manual/gos-4/en/performance.html#scan-performance");
  script_xref(name:"URL", value:"http://docs.greenbone.net/GSM-Manual/gos-4/en/vulnerabilitymanagement.html?highlight=scanner_plugins_timeout#general-preferences");

  script_tag(name:"summary", value:"The script reports if:

  - a custom scan configuration is in use without having a Port scanner from
  the 'Port scanners' family enabled.

  - a port scanner plugin was running into a timeout.

  - a required port scanner (e.g. nmap) is not installed.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

# If the host was marked as dead we probably havn't scanned
# it with a portscanner so no need to continue here...
if( get_kb_item( "Host/dead" ) ) exit( 0 );

# We have scanned the host. This is for the case if optimize_test
# is set to "no" and thus script_exclude_keys above is not evaluated.
if( get_kb_item( "Host/scanned" ) ) exit( 0 );

# If one of these options is set to no a portscanner is not
# directly required...
if( "no" >< get_preference( "unscanned_closed" ) ||
    "no" >< get_preference( "unscanned_closed_udp" ) ) {
  exit( 0 );
}

report  = "The host wasn't scanned due to the following possible reasons:";
report += '\n\n - No Port scanner plugin from the "Port scanners" family is ';
report += 'included in this scan configuration. Recommended: Nmap (NASL wrapper).';
report += '\n - The Port scanner plugin reached a timeout during the port scanning ';
report += 'phase. Please either choose a port range for this target containing less ports ';
report += 'or raise the "scanner_plugins_timeout" scanner preference to a higher timeout.';

if( ! get_kb_item( "Tools/Present/nmap" ) ) {
  report += '\n - The "nmap" binary/package is not installed or not accessible by the scanner.';
}

log_message( port:0, data:report );
exit( 0 );
