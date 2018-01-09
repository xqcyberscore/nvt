###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_windows_stuxnet_unspecified_vuln.nasl 8296 2018-01-05 07:28:01Z teissa $
#
# Microsoft Windows 32-bit Platforms Unspecified vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

tag_impact = "Successful exploitation could allow local attackers to gain privileges or
  compromise the vulnerable system via unknown vectors.
  Impact Level: Application";
tag_affected = "All Windows platforms";
tag_insight = "Unspecified privilege elevation vulnerabilities that are used by variants of
  the 'Stuxnet malware' family. Each of these vulnerabilities allow the malware
  to elevate its privileges to higher than normal user levels in order to embed
  itself into the operating system and prevent disinfection and/or detection.";
tag_solution = "Remove all Stuxnet related files found.";
tag_summary = "This host is prone to multiple unspecified vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801527");
  script_version("$Revision: 8296 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-05 08:28:01 +0100 (Fri, 05 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-10-18 15:37:53 +0200 (Mon, 18 Oct 2010)");
  script_cve_id("CVE-2010-3888", "CVE-2010-3889");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Microsoft Windows 32-bit Platforms Unspecified vulnerabilities");
  script_xref(name : "URL" , value : "http://www.virusbtn.com/conference/vb2010/abstracts/LastMinute8.xml");
  script_xref(name : "URL" , value : "http://www.virusbtn.com/conference/vb2010/abstracts/LastMinute7.xml");
  script_xref(name : "URL" , value : "http://www.securelist.com/en/blog/2291/Myrtus_and_Guava_Episode_MS10_061");
  script_xref(name : "URL" , value : "http://www.computerworld.com/s/article/9185919/Is_Stuxnet_the_best_malware_ever_");
  script_xref(name : "URL" , value : "http://www.symantec.com/connect/blogs/stuxnet-using-three-additional-zero-day-vulnerabilities");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Windows");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}

include("smb_nt.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

if( get_kb_item("SMB/samba")){
  exit(0);
}

rootfile = smb_get_systemroot();
if(!rootfile ){
  exit(0);
}

##  Filenames are hardcoded...
stux = make_list("\system32\winsta.exe",
                 "\system32\mof\sysnullevent.mof");

foreach file (stux)
{
  ## Get the path of Stuxnet file
  path = rootfile + file;
  file  = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1", string:path);
  share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:path);

  ##  Check the existence of Stuxnet file
  read = read_file(file:file, share:share, offset:0, count:30);
  if(read)
  {
    security_message(0);
    exit(0);
  }
}
