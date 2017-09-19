###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_lync_attendee_ms15-123.nasl 7174 2017-09-18 11:48:08Z asteins $
#
# Microsoft Lync Attendee Information Disclosure Vulnerability (3105872)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806156");
  script_version("$Revision: 7174 $");
  script_cve_id("CVE-2015-6061");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-09-18 13:48:08 +0200 (Mon, 18 Sep 2017) $");
  script_tag(name:"creation_date", value:"2015-11-11 10:21:46 +0530 (Wed, 11 Nov 2015)");
  script_name("Microsoft Lync Attendee Information Disclosure Vulnerability (3105872)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Bulletin MS15-123.");

  script_tag(name:"vuldetect", value:"Get the vulnerable file version and
  check appropriate patch is applied or not.");

  script_tag(name:"insight", value:"The flaws exist due to improper handling
  of JavaScript content.");

  script_tag(name:"impact", value:"Successful exploitation will allow a
  remote attacker disclosure if an attacker invites a target user to an instant
  message session and then sends that user a message containing specially crafted
  JavaScript content.

  Impact Level: System/Application");

  script_tag(name:"affected", value:"Microsoft Lync Attendee 2010");


  script_tag(name:"solution", value:"Run Windows Update and update the
  listed hotfixes or download and update mentioned hotfixes in the advisory
  from the below link,
  https://technet.microsoft.com/library/security/MS15-123");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name : "URL" , value : "https://support.microsoft.com/en-us/kb/3096738");
  script_xref(name : "URL" , value : "https://support.microsoft.com/en-us/kb/3096736");
  script_xref(name : "URL" , value : "https://support.microsoft.com/en-us/kb/3096735");
  script_xref(name : "URL" , value : "https://technet.microsoft.com/library/security/MS15-123");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_ms_lync_detect_win.nasl");
  script_mandatory_keys("MS/Lync/Attendee/Ver", "MS/Lync/Attendee/path");
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("secpod_smb_func.inc");
include("version_func.inc");

## Variables Initialization
path = "";
dllVer = "";

## For Microsoft Lync 2010 Attendee (admin level install)
## For Microsoft Lync 2010 Attendee (user level install)

## Get Installed Path
path = get_kb_item("MS/Lync/Attendee/path");
if(path)
{
  ## Get Version from Rtmpltfm.dll
  dllVer = fetch_file_version(sysPath:path, file_name:"Rtmpltfm.dll");
  if(dllVer)
  {
    ## after patch file updating to version 4.0.7577.4484 it's not mentioned in bulletin.
    if(version_in_range(version:dllVer, test_version:"4.0", test_version2:"4.0.7577.4483"))
    {

      report = 'File checked:     ' + path + "Rtmpltfm.dll" + '\n' +
               'File version:     ' + dllVer  + '\n' +
               'Vulnerable range:  4.0 - 4.0.7577.4483' + '\n' ;
      security_message(data:report);
      exit(0);
    }
  }
}
