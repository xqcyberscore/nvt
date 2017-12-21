###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_winamp_vp6_codec_bof_vuln.nasl 8187 2017-12-20 07:30:09Z teissa $
#
# Winamp VP6 Content Parsing Buffer Overflow Vulnerability
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

tag_impact = "Successful exploitation will allow attackers to execute arbitrary code or
  can  be exploited by malicious people to potentially compromise a user's
  system.
  Impact Level: Application.";
tag_affected = "Winamp version before 5.59 Beta build 3033 (5.5.9.3033)";

tag_insight = "The flaw is caused by an error in the VP6 codec (vp6.w5s) when parsing VP6
  video content. This can be exploited to cause a heap-based buffer overflow
  via a specially crafted media file or stream.";
tag_solution = "upgrade to Winamp 5.59 Beta build 3033 or later,
  For updates refer to http://www.winamp.com/media-player";
tag_summary = "This host is installed with Winamp and is prone to heap-based
  buffer overflow vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801542");
  script_version("$Revision: 8187 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-20 08:30:09 +0100 (Wed, 20 Dec 2017) $");
  script_tag(name:"creation_date", value:"2010-11-16 10:37:01 +0100 (Tue, 16 Nov 2010)");
  script_cve_id("CVE-2010-1523");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Winamp VP6 Content Parsing Buffer Overflow Vulnerability");
  script_xref(name : "URL" , value : "http://secunia.com/secunia_research/2010-95/");
  script_xref(name : "URL" , value : "http://forums.winamp.com/showthread.php?t=322995");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/archive/1/514484/100/0/threaded");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("secpod_winamp_detect.nasl");
  script_require_keys("Winamp/Version");
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

winampVer = get_kb_item("Winamp/Version");
if(!winampVer){
  exit(0);
}

# Check for version less than 5.5.9.3033 (5.59 Beta build 3033)
if(version_is_less(version:winampVer, test_version:"5.5.9.3033"))
{
  winPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion" +
                                "\App Paths\winamp.exe", item:"Path");
  if(!winPath){
    exit(0);
  }

  winPath =  winPath + "\System\vp6.w5s";
  share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:winPath);
  file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:winPath);
  dllSize = get_file_size(share:share, file:file);
  if(dllSize){
    security_message(0);
  }
}
