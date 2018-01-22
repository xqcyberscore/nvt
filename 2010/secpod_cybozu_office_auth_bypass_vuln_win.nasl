###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_cybozu_office_auth_bypass_vuln_win.nasl 8469 2018-01-19 07:58:21Z teissa $
#
# Cybozu Office Authentication Bypass Vulnerability (Windows)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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

tag_impact = "Successful exploitation will allow remote attackers to bypass authentication
  and obtain or modify sensitive information by using the unique ID of the
  'user&qts' cell phone.
  Impact Level: Application.";
tag_affected = "Cybozu Office before 8 (8.1.0.1).";

tag_insight = "The flaw exists due to insufficient checks being performed when accessing
  the 'login' interface.";
tag_solution = "Upgrade to Cybozu Office 8 (8.1.0.1).
  For updates refer to http://products.cybozu.co.jp/office";
tag_summary = "This host is installed with Cybozu Office and is prone to
  authentication bypass vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902060");
  script_version("$Revision: 8469 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-19 08:58:21 +0100 (Fri, 19 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-06-01 15:40:11 +0200 (Tue, 01 Jun 2010)");
  script_cve_id("CVE-2010-2029");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_name("Cybozu Office Authentication Bypass Vulnerability (Windows)");


  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("General");
  script_dependencies("secpod_reg_enum.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/39508");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/57976");
  script_xref(name : "URL" , value : "http://jvn.jp/en/jp/JVN87730223/index.html");
  script_xref(name : "URL" , value : "http://www.ipa.go.jp/security/english/vuln/201004_cybozu_en.html");
  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

if(!registry_key_exists(key:"SOFTWARE\Cybozu, Inc.")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";

if(!registry_key_exists(key:key)){
    exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  cbofName = registry_get_sz(key:key + item, item:"Publisher");

  ## Check the name of the application
  if("Cybozu, Inc." >< cbofName)
  {
    ## Check for the version
    cbofVer = registry_get_sz(key:key + item, item:"DisplayVersion");
    if (cbofVer != NULL)
    {
      ## Check for Cybozu office version <= 8 (8.1.0.1)
       if(version_is_less(version:cbofVer, test_version:"8.1.0.1")){
         security_message(0) ;
      }
    }
  }
}
