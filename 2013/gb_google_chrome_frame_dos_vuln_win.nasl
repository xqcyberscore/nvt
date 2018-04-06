###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_google_chrome_frame_dos_vuln_win.nasl 9353 2018-04-06 07:14:20Z cfischer $
#
# Google Chrome Frame Plugin For Microsoft IE Denial Of Service Vulnerability (Windows)
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploitation will allow remote attacker to crash the
  program via a specially crafted _blank value for the target
  attribute of an A element.
  Impact Level: Application";

tag_affected = "Google Chrome Frame plugin version before 26.0.1410.28";
tag_insight = "Flaw due to an improper handling of an attach tab request in the
  Hook_Terminate function in chrome_frame/protocol_sink_wrap.cc.";
tag_solution = "Upgrade to Google Chrome Frame plugin 26.0.1410.28 or later,
  For updates refer to http://www.google.com/chromeframe";
tag_summary = "This host is installed with google chrome frame plugin for
  microsoft ie and is prone to denial of service vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803461");
  script_version("$Revision: 9353 $");
  script_cve_id("CVE-2013-2493");
  script_bugtraq_id(58562);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:14:20 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2013-04-02 12:21:11 +0530 (Tue, 02 Apr 2013)");
  script_name("Google Chrome Frame Plugin For Microsoft IE Denial Of Service Vulnerability (Windows)");
  script_xref(name : "URL" , value : "https://chromiumcodereview.appspot.com/12395021");
  script_xref(name : "URL" , value : "https://code.google.com/p/chromium/issues/detail?id=178415");
  script_xref(name : "URL" , value : "http://googlechromereleases.blogspot.in/2013/03/beta-channel-update.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_ms_ie_detect.nasl");
  script_mandatory_keys("MS/IE/Version");
  script_require_ports(139, 445);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");
include("smb_nt.inc");
include("secpod_smb_func.inc");

## Variable Initialization
ver = "";
name = "";
key= "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Google Chrome Frame";

# Check for Google Chrome Frame Installation
if(!registry_key_exists(key: key)){
  exit(0);
}

name = registry_get_sz(item:"DisplayName", key: key);
if("Google Chrome Frame" >< name)
{
  # Get Google Chrome Frame Version from Registry Entry
  ver = registry_get_sz(item:"Version", key: key);

  if(ver)
  {
    if(version_is_less(version:ver, test_version:"26.0.1410.28"))
    {
      security_message(0);
      exit(0);
    }
  }
}
