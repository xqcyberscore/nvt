###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_novell_iprint_client_mult_code_exec_vuln.nasl 9352 2018-04-06 07:13:02Z cfischer $
#
# Novell iPrint Client Multiple Remote Code Execution Vulnerabilities
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2012 SecPod, http://www.secpod.com
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

CPE = "cpe:/a:novell:iprint";

tag_impact = "Successful exploitation could allow attackers to execute arbitrary code,
  cause buffer overflow or a denial of service condition.
  Impact Level: System/Application";
tag_affected = "Novell iPrint Client version prior to 5.78";

tag_insight = "The flaws are due to
  - An error in nipplib.dll within the 'GetDriverSettings()' function.
  - An error within the 'GetPrinterURLList2()' function in the ActiveX Control,
    when handling overly long string parameters.
  - A boundary error within nipplib.dll, when parsing the 'client-file-name'
    parameter.";
tag_solution = "Upgrade to the Novell iPrint Client version 5.78 or later,
  For updates refer to http://download.novell.com/Download?buildid=6_bNby38ERg~";
tag_summary = "This host is installed with Novell iPrint Client and is prone to
  multiple remote code execution vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902674");
  script_version("$Revision: 9352 $");
  script_cve_id("CVE-2011-4185", "CVE-2011-4186", "CVE-2011-4187");
  script_bugtraq_id(51926);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2012-04-26 12:20:02 +0530 (Thu, 26 Apr 2012)");
  script_name("Novell iPrint Client Multiple Remote Code Execution Vulnerabilities");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/47867/");
  script_xref(name : "URL" , value : "http://securitytracker.com/id/1026660");
  script_xref(name : "URL" , value : "http://www.novell.com/support/kb/doc.php?id=7010143");
  script_xref(name : "URL" , value : "http://www.novell.com/support/kb/doc.php?id=7010144");
  script_xref(name : "URL" , value : "http://www.novell.com/support/kb/doc.php?id=7010145");
  script_xref(name : "URL" , value : "http://www.novell.com/support/kb/doc.php?id=7008708");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 SecPod");
  script_family("General");
  script_dependencies("secpod_novell_prdts_detect_win.nasl");
  script_mandatory_keys("Novell/iPrint/Installed");
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE );
vers = infos['version'];
path = infos['location'];

## Check for Novell iPrint Client Version less than 5.78(05.78.00)
if( version_is_less( version:vers, test_version:"5.78" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"5.78", install_path:path );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );