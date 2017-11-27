###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_gsm_manager_auth_bypass_11_13.nasl 7888 2017-11-23 14:20:55Z asteins $
#
# GSM Manager Authentication Bypass
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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

CPE = "cpe:/o:greenbone:greenbone_os";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103832");
  script_version("$Revision: 7888 $");
  script_cve_id("CVE-2013-6765");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-11-23 15:20:55 +0100 (Thu, 23 Nov 2017) $");
  script_tag(name:"creation_date", value:"2013-11-08 13:02:55 +0200 (Fri, 08 Nov 2013)");
  script_name("GSM Manager Authentication Bypass");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("gb_openvas_manager_detect.nasl", "gb_greenbone_os_detect.nasl");
  script_mandatory_keys("greenbone/gos/detected");

  tag_impact = "Attackers can exploit these issues to gain unauthorized access to the
  affected application and perform certain actions.";

  tag_insight = "A software bug in the server module 'OpenVAS Manager' allowed to bypass the OMP
  authentication procedure. The attack vector is remotely available in case public OMP is enabled.
  In case of successful attack, the attacker gains partial rights to execute OMP commands. The bypass
  authentication is, however, incomplete and several OMP commands will fail to execute properly.";

  tag_affected = "Greenbone OS 2.2.0-1 up to 2.2.0-19 when public OMP is enabled.";
  tag_summary = "The remote GSM Manager is prone to an authentication bypass.";

  tag_solution = " Upgrade at least to Greenbone OS 2.2.0-20.
  Temporary workaround: Disable public OMP.";

  tag_vuldetect = "If public OMP is enabled, try to bypass OMP authentication by sending a special crafted request.
  If public OMP is not enabled, check the GOS version.";

  script_tag(name:"impact", value:tag_impact);
  script_tag(name:"vuldetect", value:tag_vuldetect);
  script_tag(name:"insight", value:tag_insight);
  script_tag(name:"solution", value:tag_solution);
  script_tag(name:"summary", value:tag_summary);
  script_tag(name:"affected", value:tag_affected);

  script_xref(name:"URL", value:"http://greenbone.net/technology/gbsa2013-01.html");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("host_details.inc");
include( "version_func.inc" );

if( ! get_kb_item( "greenbone/gos/detected" ) ) exit( 0 );

# public omp enabled
if( port = get_app_port( cpe:"cpe:/a:openvas:openvas_manager" ) ) {

  soc = open_sock_tcp( port );
  if( ! soc ) exit( 0 );

  send( socket:soc, data:'<get_version/><get_targets/>\r\n' );
  ret = recv( socket:soc, length: 1024 );
  close( soc );

  if( "get_targets_response" >< ret && "target id" >< ret ) {
    security_message( port:port );
    exit( 0 );
  }
# public omp disabled
} else {

  if( ! vers = get_kb_item( "greenbone/gos/version" ) ) exit( 0 );
  vers = str_replace( string:vers, find:"-", replace:"." );

  if( version_is_less( version:vers, test_version:"2.2.0.20" ) ) {
    report = report_fixed_ver( installed_version:vers, fixed_version:"2.2.0-20" );
    security_message( port:0, data:report );
    exit( 0 );
  }
}

exit( 99 );
