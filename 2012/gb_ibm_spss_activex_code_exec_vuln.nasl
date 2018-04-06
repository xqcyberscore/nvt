###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_spss_activex_code_exec_vuln.nasl 9352 2018-04-06 07:13:02Z cfischer $
#
# IBM SPSS SamplePower 'VsVIEW6' ActiveX Control Multiple Code Execution Vulnerabilities (Windows)
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:ibm:spss_samplepower";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.

A workaround is to disable the use of the vulnerable ActiveX control within
Internet Explorer or Set the killbit for the following CLSID
{6E84D662-9599-11D2-9367-20CC03C10627}. For more info please refer the below link,
http://support.microsoft.com/kb/240797";

tag_impact = "Successful exploitation could allow remote attackers to execute
arbitrary code in the context of the application using the ActiveX control.
Failed exploit attempts will likely result in denial-of-service conditions.

Impact Level: System/Application";

tag_affected = "IBM SPSS SamplePower version 3.0";

tag_insight = "Multiple flaws are due to unspecified errors in the VsVIEW6
ActiveX Control (VsVIEW6.ocx) when handling the 'SaveDoc()' and 'PrintFile()'
methods.";

tag_summary = "This host is installed with IBM SPSS SamplePower and is prone
to buffer overflow vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802600");
  script_version("$Revision: 9352 $");
  script_bugtraq_id(51448);
  script_cve_id("CVE-2012-0189");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2012-02-01 11:11:11 +0530 (Wed, 01 Feb 2012)");
  script_name("IBM SPSS SamplePower 'VsVIEW6' ActiveX Control Multiple Code Execution Vulnerabilities (Windows)");

  script_xref(name : "URL" , value : "http://secunia.com/advisories/47605");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/51448");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/72119");
  script_xref(name : "URL" , value : "http://www-01.ibm.com/support/docview.wss?uid=swg21577951");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_ibm_spss_sample_power_detect_win.nasl");
  script_mandatory_keys("IBM/SPSS/Win/Installed");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");
include("secpod_activex.inc");
include("host_details.inc");

infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE );
vers = infos['version'];
path = infos['location'];

## Check for IBM SPSS SamplePower 3.0
if( version_is_equal( version:vers, test_version:"3.0" ) ) {

  ## CLSID
  clsid = "{6E84D662-9599-11D2-9367-20CC03C10627}";

  ## Check if Kill-Bit is set
  if( is_killbit_set( clsid:clsid ) == 0 ) {
    report = "Installed version is 3.0 and Kill-Bit for CLSID " + clsid + " is not set.";
    security_message( port:0, data:report );
    exit( 0 );
  }
}

exit( 99 );