###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_internet_download_manager_bof_vuln.nasl 8266 2018-01-01 07:28:32Z teissa $
#
# Internet Download Manager FTP Buffer Overflow Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploitation will allow remote attackers to execute arbitrary code.
  Impact Level: Application.";
tag_affected = "Internet Download Manager version prior to 5.19";

tag_insight = "The flaw exists due to boundary error when sending certain test sequences to
  an 'FTP' server, which leads a stack-based buffer overflow by tricking a user
  into downloading a file from a specially crafted FTP URI.";
tag_solution = "Upgrade to the Internet Download Manager 5.19
  For updates refer to http://www.internetdownloadmanager.com/download.html";
tag_summary = "This host is installed with Internet Download Manager and is prone
  to buffer overflow vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800776");
  script_version("$Revision: 8266 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-01 08:28:32 +0100 (Mon, 01 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-05-19 14:50:39 +0200 (Wed, 19 May 2010)");
  script_cve_id("CVE-2010-0995");
  script_bugtraq_id(39822);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Internet Download Manager FTP Buffer Overflow Vulnerability");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/39446");
  script_xref(name : "URL" , value : "http://secunia.com/secunia_research/2010-62/");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/archive/1/511060/100/0/threaded");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Buffer overflow");
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

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" +
       "\Internet Download Manager";
if(!registry_key_exists(key:key)){
  exit(0);
}

## Check for Internet Download Manager DisplayName
idmName = registry_get_sz(key:key, item:"DisplayName");
if("Internet Download Manager" >< idmName)
{
  ## Check for Internet Download Manager DisplayIcon
  idmPath = registry_get_sz(key:key + item, item:"DisplayIcon");

  if(!isnull(idmPath))
  {
    share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:idmPath);
    fire = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:idmPath);

    ## Check for Internet Download Manager .exe File Version
    idmVer = GetVer(file:fire, share:share);
    if(idmVer != NULL)
    {
      ## Check for Internet Download Manager versiom less that '5.19'
      if(version_is_less(version:idmVer, test_version:"5.19.2.1")){
        security_message(0) ;
      }
    }
  }
}
