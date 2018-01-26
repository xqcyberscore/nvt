###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_microsoft_office_detect_macosx.nasl 8539 2018-01-25 14:37:09Z gveerendra $
#
# Microsoft Office Version Detection (Mac OS X)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802431");
  script_version("$Revision: 8539 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-01-25 15:37:09 +0100 (Thu, 25 Jan 2018) $");
  script_tag(name:"creation_date", value:"2012-05-09 10:50:16 +0530 (Wed, 09 May 2012)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft Office Version Detection (Mac OS X)");

  tag_summary =
"Detection of installed version of Microsoft Office.

The script logs in via ssh, and searches for Microsoft Office '.app' folder
and queries the related 'Info.plist' file for string'CFBundleShortVersionString'
via command line option 'defaults read'.";


  script_tag(name : "summary" , value : tag_summary);
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_dependencies("gather-package-list.nasl");
  script_family("Product detection");
  script_mandatory_keys("ssh/login/osx_name");
  exit(0);
}


include("ssh_func.inc");
include("cpe.inc");
include("host_details.inc");

## Checking OS
sock = ssh_login_or_reuse_connection();
if(!sock){
  exit(0);
}

## Checking for Mac OS X
if (!get_kb_item("ssh/login/osx_name"))
{
  close(sock);
  exit(0);
}

## Check for each OS
foreach offVer (make_list("2008", "2011"))
{
  offVersion = chomp(ssh_cmd(socket:sock, cmd:"defaults read  /Applications/" +
               "Microsoft\ Office\ " + offVer +  "/Microsoft\ Document\ " +
               "Connection.app/Contents/Info CFBundleShortVersionString"));
  location =  "/Applications/Microsoft\ Office\ " + offVer +
              "/Microsoft\ Document\ Connection.app/Contents/Info.plist";

  if("does not exist" >< offVersion){
    continue;
  }
}

if(!offVersion)
{
  ## Excel.app , OneNote.app, PowerPoint.app, Outlook.app, Word.app comes after office 2016 installtuion on mac
  offname = chomp(ssh_cmd(socket:sock, cmd:"ls /Applications"));

  ver = eregmatch( pattern:'(Excel|OneNote|PowerPoint|Outlook|Word).app', string:offname );

  if(ver[0])
  {
    ## confirming office 2016 from office application
    offname = chomp(ssh_cmd(socket:sock, cmd:"defaults read  /Applications/" +
                   "Microsoft\ " + ver[0] + "/Contents/Info CFBundleGetInfoString"));
    
    offname = eregmatch( pattern:'([0-9.]+) .*Microsoft Corporation', string:offname);
 
    ## confirm office 2016
    if(offname && offname[1] =~ "^(15|16)\.")
    {
      offVer = "2016";
      location =  "/Applications/Microsoft\ " + ver[0] + "/Contents/Info.plist";

      ## get version
      offVersion = offname[1];

      ## Exit if not getting version
      if(!offVersion){
        exit(0);
      }
    }
  }
}

if(offVersion)
{
  set_kb_item(name: "MS/Office/MacOSX/Ver", value:offVersion);
  ## build cpe and store it as host_detail
  cpe = build_cpe(value:offVersion, exp:"^([0-9.]+)",
                  base: "cpe:/a:microsoft:office:" + offVer + "::mac:");
  if(isnull(cpe))
    cpe='cpe:/a:microsoft:office';

  register_product(cpe:cpe, location:location);

  log_message(data: build_detection_report(app: "Microsoft Office",
                                           version: offVersion,
                                           install: location,
                                           cpe: cpe,
                                           concluded: "Microsoft Office " + offVer + ": " + offVersion));
}

## Close Socket
close(sock);
