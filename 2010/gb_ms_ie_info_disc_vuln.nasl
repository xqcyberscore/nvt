###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_ie_info_disc_vuln.nasl 5368 2017-02-20 14:34:16Z cfi $
#
# Microsoft Internet Explorer 'mshtml.dll' Information Disclosure Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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

tag_impact = "Successful exploitation will allow attackers to gain access to
sensitive information that may aid in further attacks.

Impact Level: Application";

tag_affected = "Microsoft Internet Explorer version 8 and prior.";

tag_insight = "The CTimeoutEventList::InsertIntoTimeoutList function in Microsoft
mshtml.dll uses a certain pointer value as part of producing Timer ID values for
the setTimeout and setInterval methods in VBScript and JScript, which allows
remote attackers to obtain sensitive information about the heap memory
addresses used by the Internet Explorer application.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "This host is installed with Internet Explorer and is prone to
information disclosure vulnerability.";

if(description)
{
  script_id(801606);
  script_version("$Revision: 5368 $");
  script_tag(name:"last_modification", value:"$Date: 2017-02-20 15:34:16 +0100 (Mon, 20 Feb 2017) $");
  script_tag(name:"creation_date", value:"2010-10-18 15:37:53 +0200 (Mon, 18 Oct 2010)");
  script_bugtraq_id(41247);
  script_cve_id("CVE-2010-3886");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_name("Microsoft Internet Explorer 'mshtml.dll' Information Disclosure Vulnerability");


  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_ms_ie_detect.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "MS/IE/Version");
  script_require_ports(139, 445);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"solution_type", value:"WillNotFix");
  script_xref(name : "URL" , value : "http://archives.neohapsis.com/archives/bugtraq/2010-06/0259.html");
  script_xref(name : "URL" , value : "http://reversemode.com/index.php?option=com_content&task=view&id=68&Itemid=1");
  script_xref(name : "URL" , value : "http://www.eeye.com/Resources/Security-Center/Research/Zero-Day-Tracker/2010/20100630");
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

exit(0); ## Plugin may result to FP

## This function will return the version of the given file
function get_file_version(dllPath, file_name)
{
  share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:dllPath);
  file =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1",
                       string:dllPath + "\" + file_name);

  dllVer = GetVer(file:file, share:share);
  if(!dllVer){
    return(FALSE);
  }

  return(dllVer);
}

## Get IE Version from KB
ieVer = get_kb_item("MS/IE/Version");
if(!ieVer){
  exit(0);
}

if(version_is_less(version:ieVer, test_version:"9"))
{
  ## Get System32 path
  dllPath = registry_get_sz(key:"SOFTWARE\Microsoft\COM3\Setup",
                          item:"Install Path");
  if(dllPath)
  {
    dllVer = get_file_version(dllPath, file_name:"mshtml.dll");
    if(!isnull(dllVer))
    {
      security_message(0);
      exit(0);
    }
  }

  dllPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
                      item:"PathName");
  if(!dllPath){
    exit(0);
  }

  dllVer = get_file_version(dllPath, file_name:"system32\mshtml.dll");
  if(!isnull(dllVer)) {
    security_message(0);
  }
}
