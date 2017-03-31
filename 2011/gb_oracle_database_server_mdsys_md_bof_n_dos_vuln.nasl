###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_oracle_database_server_mdsys_md_bof_n_dos_vuln.nasl 4921 2017-01-02 16:16:25Z cfi $
#
# Oracle Database Server MDSYS.MD Buffer Overflows and Denial of Service Vulnerabilities
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:oracle:database_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802523");
  script_version("$Revision: 4921 $");
  script_cve_id("CVE-2007-0272");
  script_bugtraq_id(22083);
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-01-02 17:16:25 +0100 (Mon, 02 Jan 2017) $");
  script_tag(name:"creation_date", value:"2011-12-07 12:25:28 +0530 (Wed, 07 Dec 2011)");
  script_name("Oracle Database Server MDSYS.MD Buffer Overflows and Denial of Service Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Databases");
  script_dependencies("oracle_tnslsnr_version.nasl");
  script_mandatory_keys("OracleDatabaseServer/installed");

  script_xref(name:"URL", value:"http://securitytracker.com/id?1017522");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/31541");
  script_xref(name:"URL", value:"http://www.us-cert.gov/cas/techalerts/TA07-017A.html");
  script_xref(name:"URL", value:"http://www.appsecinc.com/resources/alerts/oracle/2007-05.shtml");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/474047/100/0/threaded");

  tag_impact = "Successful exploitation allows an attacker to execute arbitrary code. It
  can also be exploited to cause denial of service by killing Oracle server process.

  Impact Level: Application";

  tag_affected = "Oracle Database server versions 8.1.7.4, 9.0.1.5, 9.2.0.7, and 10.1.0.4";

  tag_insight = "The flaws are due to error in 'MDSYS.MD' package that is used in the
  Oracle spatial component. The package has EXECUTE permission to PUBLIC, so
  any Oracle database user can exploit the vulnerability to execute arbitrary code.";

  tag_solution = "Apply patches from below link,
  http://www.oracle.com/technetwork/topics/security/cpujan2007-101493.html";

  tag_summary = "This host is running Oracle database and is prone to buffer
  overflow and denial of service vulnerabilities.";

  script_tag(name:"impact", value:tag_impact);
  script_tag(name:"affected", value:tag_affected);
  script_tag(name:"insight", value:tag_insight);
  script_tag(name:"summary", value:tag_summary);
  script_tag(name:"solution", value:tag_solution);

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_in_range( version:vers, test_version:"8.1.0", test_version2:"8.1.7.3" ) ||
    version_in_range( version:vers, test_version:"10.1.0", test_version2:"10.1.0.3" ) ||
    version_in_range( version:vers, test_version:"9.0.1", test_version2:"9.0.1.4" ) ||
    version_in_range( version:vers, test_version:"9.2.0", test_version2:"9.2.0.6" ) ||
    version_is_equal( version:vers, test_version:"8.1.7.4" ) ||
    version_is_equal( version:vers, test_version:"9.0.1.5" ) ||
    version_is_equal( version:vers, test_version:"10.1.0.4" ) ||
    version_is_equal( version:vers, test_version:"9.2.0.7" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"See references" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );