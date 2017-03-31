###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_marcelo_costa_fileserver_dir_trav_vuln.nasl 5055 2017-01-20 14:08:39Z teissa $
#
# Marcelo Costa FileServer Component Directory Traversal Vulnerability
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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

tag_impact = "Successful exploitation will allow attackers to cause Directory
Traversal attacks on the affected product.

Impact Level: System/Application";

tag_affected = "Marcelo Costa FileServer version 1.0";

tag_insight = "Error in the FileServer component which may allows remote
authenticated users to list arbitrary directories and read arbitrary files via
a .. (dot dot) in a pathname.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "This host is running Marcelo Costa FileServer with Windows Live
Messenger and Messenger Plus! Live, and is prone to directory traversal
vulnerability.";

if(description)
{
  script_id(900810);
  script_version("$Revision: 5055 $");
  script_tag(name:"last_modification", value:"$Date: 2017-01-20 15:08:39 +0100 (Fri, 20 Jan 2017) $");
  script_tag(name:"creation_date", value:"2009-08-05 14:14:14 +0200 (Wed, 05 Aug 2009)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:N/A:N");
  script_cve_id("CVE-2009-2544");
  script_name("Marcelo Costa FileServer Component Directory Traversal Vulnerability");

  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/9093");
  script_xref(name : "URL" , value : "http://en.securitylab.ru/nvd/382773.php");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("General");
  script_dependencies("gb_ms_win_live_messenger_detect.nasl");
  script_mandatory_keys("MS/MessengerPlus/Ver", "MS/MessengerPlus/Path");
  script_require_ports(139, 445);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if( ! version = get_kb_item( "MS/MessengerPlus/Ver" ) ) exit( 0 );

# Check for Messenger Plus! Live Installation
if( version =~ "^4\..*")
{
  # Get for Installed Location of Messenger Plus! Live
  plusPath = get_kb_item("MS/MessengerPlus/Path");

  if(isnull(plusPath)){
    exit(0);
  }

  fsPath = NULL;
  if("\Uninstall.exe" >< plusPath)
    fsPath = plusPath - "\Uninstall.exe" + "\Scripts\FileServer\fsVersion.txt";
  else if("\MsgPlus.exe" >< plusPath)
    fsPath = plusPath - "\MsgPlus.exe" + "\Scripts\FileServer\fsVersion.txt";

  if(!isnull(fsPath))
  {
    share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:fsPath);
    file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:fsPath);

    # Read the FileServer fsVersion.txt File
    fileSrvTxt = read_file(share:share, file:file, offset:0, count:100);

    if(isnull(fileSrvTxt)){
      exit(0);
    }
    # Grep for FileServer Version
    costaVer = egrep(pattern:"[0-9.]+", string:fileSrvTxt);

    # Check for FileServer Version
    if(costaVer && version_is_equal(version:costaVer, test_version:"1.0")){
      security_message(0);
    }
  }
}
