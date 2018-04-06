###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cogent_cascade_n_opc_datahub_mult_vuln.nasl 9352 2018-04-06 07:13:02Z cfischer $
#
# Cogent OPC DataHub and Cascade DataHub XSS and CRLF Vulnerabilities
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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

tag_impact = "Successful exploitation could allow remote attackers to execute arbitrary
  HTML and script code in a user's browser session in context of an affected
  site.
  Impact Level: Application.";
tag_affected = "OPC DataHub version 6.4.20 and prior
  Cascade DataHub version 6.4.20 and prior";

tag_insight = "The flaws are due to unspecified errors in the applications, allows
  remote attackers to inject arbitrary web script or HTML via unspecified
  vectors.";
tag_solution = "Upgrade to the OPC DataHub version 7.2 0r later
  Upgrade to the Cascade DataHub version 7.2 0r later
  For updates refer to http://www.cogentdatahub.com/index.html";
tag_summary = "This host is installed with OPC DataHub or Cascade DataHub and is
  prone to cross site scripting and CRLF vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802565");
  script_version("$Revision: 9352 $");
  script_cve_id("CVE-2012-0310", "CVE-2012-0309");
  script_bugtraq_id(51375);
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2012-01-20 18:01:09 +0530 (Fri, 20 Jan 2012)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_name("Cogent OPC DataHub and Cascade DataHub XSS and CRLF Vulnerabilities");
  script_xref(name : "URL" , value : "http://jvn.jp/en/jp/JVN12983784/index.html");
  script_xref(name : "URL" , value : "http://jvn.jp/en/jp/JVN63249231/index.html");
  script_xref(name : "URL" , value : "http://jvndb.jvn.jp/en/contents/2012/JVNDB-2012-000001.html");
  script_xref(name : "URL" , value : "http://jvndb.jvn.jp/en/contents/2012/JVNDB-2012-000002.html");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_reg_enum.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

## Function to check the version
function version_check(ver)
{
  if(version_is_less_equal(version:ver, test_version:"6.4.20"))
  {
    security_message(0);
    exit(0);
  }
}

## Checking for OPC DataHub
if(registry_key_exists(key:"SOFTWARE\Cogent\OPC DataHub"))
{
  key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\OPC DataHub";
  if(registry_key_exists(key:key))
  {
    ## Get the version from registry for OPC DataHub
    dataVer = registry_get_sz(key:key, item:"DisplayVersion");
    if(dataVer){
      version_check(ver:dataVer);
    }
  }
}


## Checking for Cascade DataHub
if(registry_key_exists(key:"SOFTWARE\Cogent\Cascade DataHub"))
{
  key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Cascade DataHub";
  if(!(registry_key_exists(key:key))){
    exit(0);
  }

  ## Get the version from registry for Cascade DataHub
  dataVer = registry_get_sz(key:key, item:"DisplayVersion");
  if(!dataVer){
    exit(0);
  }
  version_check(ver:dataVer);
}
