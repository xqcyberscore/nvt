###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_kingview_heap_bof_vuln.nasl 9352 2018-04-06 07:13:02Z cfischer $
#
# WellinTech KingView 'HistoryServer.exe' Heap Based Buffer Overflow Vulnerability
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

tag_impact = "Successful exploitation will allow remote attackers to execute arbitrary
  code in the context of the application. Failed attacks will cause
  denial-of-service conditions.
  Impact Level: System/Application";
tag_affected = "KingView version 6.53 and 65.30.2010.18018";

tag_solution = "Apply the patch from below link
  http://www.kingview.com/news/detail.aspx?contentid=587

  *****
  NOTE : Ignore this warning, if above mentioned patch is applied already.
  *****";

tag_insight = "The flaw is due to an error in the 'nettransdll.dll' module of the
  'HistorySvr' component when processing a packet containing opcode 3. This can
  be exploited to cause a heap-based buffer overflow via a specially crafted
  packet sent to TCP port 777.";
tag_summary = "This host is installed with KingView and is prone to heap based
  buffer overflow vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802550");
  script_version("$Revision: 9352 $");
  script_cve_id("CVE-2011-4536");
  script_bugtraq_id(51159);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2012-01-02 14:11:32 +0530 (Mon, 02 Jan 2012)");
  script_name("WellinTech KingView 'HistoryServer.exe' Heap Based Buffer Overflow Vulnerability");

  script_xref(name : "URL" , value : "http://secunia.com/advisories/47339");
  script_xref(name : "URL" , value : "http://www.kingview.com/news/detail.aspx?contentid=587");
  script_xref(name : "URL" , value : "http://www.zerodayinitiative.com/advisories/ZDI-11-351/");
  script_xref(name : "URL" , value : "http://www.us-cert.gov/control_systems/pdf/ICSA-11-355-02.pdf");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("secpod_reg_enum.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "solution" , value : tag_solution);
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

if(!registry_key_exists(key:"SOFTWARE\WellinControl Technology Development Co.,Ltd.")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";

if(!registry_key_exists(key:key)){
  exit(0);
}

foreach item(registry_enum_keys(key:key))
{
  kvName = registry_get_sz(key:key + item, item:"DisplayName");

  ## Check DisplayName for KingView
  if("Kingview" >< kvName)
  {
    ## Get KingView version
    kvVer = registry_get_sz(key:key + item, item:"DisplayVersion");
    if(kvVer!= NULL)
    {
      ## Check for vulnerables KingView versions
      if(version_is_equal(version:kvVer, test_version:"6.53"))
      {
        ## Get the 'nettransdll.dll' file version
        dllPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion",
                          item:"ProgramFilesDir");
        if(dllPath)
        {
          dllVer = fetch_file_version(sysPath:dllPath, file_name:"Kingview\nettransdll.dll");
          {
            ## Check 'nettransdll.dll' less than 65.30.2010.18018
            if(version_is_less(version:dllVer, test_version:"65.30.2010.18018"))
            {
              security_message(0);
              exit(0);
            }
          }
        }
      }
    }
  }
}
