##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_novell_edirectory_dos_vuln.nasl 5190 2017-02-03 11:52:51Z cfi $
#
# Novell eDirectory NCP Request Remote Denial of Service Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:novell:edirectory";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902291");
  script_version("$Revision: 5190 $");
  script_cve_id("CVE-2010-4327");
  script_bugtraq_id(46263);
  script_tag(name:"last_modification", value:"$Date: 2017-02-03 12:52:51 +0100 (Fri, 03 Feb 2017) $");
  script_tag(name:"creation_date", value:"2011-02-23 12:24:37 +0100 (Wed, 23 Feb 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Novell eDirectory NCP Request Remote Denial of Service Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Denial of Service");
  script_dependencies("novell_edirectory_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/ldap", 389, 636);
  script_mandatory_keys("Host/runs_unixoide", "eDirectory/installed");

  script_xref(name:"URL", value:"http://secunia.com/advisories/43186");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2011/0305");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-060/");
  script_xref(name:"URL", value:"http://www.novell.com/support/viewContent.do?externalId=7007781&sliceId=2");

  tag_impact = "Successful exploitation will allow remote attackers to cause a vulnerable
  service to become unresponsive, leading to a denial of service condition.

  Impact Level: Application.";

  tag_affected = "Novell eDirectory 8.8.5 before 8.8.5.6 (8.8.5.SP6)
  Novell eDirectory 8.8.6 before 8.8.6.2 (8.8.6.SP2) on Linux.";

  tag_insight = "This flaw is caused by an error in the 'NCP' implementation when processing
  malformed 'FileSetLock' requests sent to port 524.";

  tag_solution = "Upgrade to Novell eDirectory  8.8.5.6 or  8.8.6.2
  For updates refer to http://www.novell.com/products/edirectory/";

  tag_summary = "This host is running Novell eDirectory is prone to denial of
  service vulnerability.";

  script_tag(name:"insight", value:tag_insight);
  script_tag(name:"solution", value:tag_solution);
  script_tag(name:"summary", value:tag_summary);
  script_tag(name:"impact", value:tag_impact);
  script_tag(name:"affected", value:tag_affected);

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

# only eDirectory running under Linux is affected
if( host_runs( "windows" ) == "yes" ) exit( 0 );

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! get_app_version( cpe:CPE, port:port ) ) exit( 0 );

## Get the version from KB
edirVer = get_kb_item(string("ldap/", port,"/eDirectory"));
if(isnull(edirVer)){
 exit(0);
}

edirVer = eregmatch(pattern:"(([0-9.]+).?([a-zA-Z0-9]+)?)", string:edirVer);
if(!isnull(edirVer[1]))
{
  ## Check for vulnerable versions
  edirVer = ereg_replace(pattern:"-| ", replace:".", string:edirVer[1]);
  if(version_in_range(version:edirVer, test_version:"8.8.5", test_version2:"8.8.5.SP5") ||
     version_in_range(version:edirVer, test_version:"8.8.6", test_version2:"8.8.6.SP1")) {
    security_message( port:port );
    exit( 0 );
  }
}

exit( 99 );