###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mozilla_prdts_detect_macosx.nasl 8180 2017-12-19 14:11:38Z cfischer $
#
# Mozilla Products Version Detection (Mac OS X)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Update By:  Rachana Shetty <srachana@secpod.com> on 2012-11-27
# Updated to detect ESR versions and according to CR-57
#
# Update By:  Thanga Prakash S <tprakash@secpod.com> on 2013-09-23
# According to new style script_tags and Fixed issue in identifying ESR.
#
# Updated By: Kashinath T <tkashinath@secpod.com> on 2016-04-05
# Updated to detect newer version of Mozilla Firefox ESR
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.802179");
  script_version("$Revision: 8180 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-12-19 15:11:38 +0100 (Tue, 19 Dec 2017) $");
  script_tag(name:"creation_date", value:"2011-10-14 14:22:41 +0200 (Fri, 14 Oct 2011)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Mozilla Products Version Detection (Mac OS X)");

  tag_summary = "Detection of installed version of Mozilla products on Max OS X.

The script logs in via ssh, searches for folder Mozilla products '.app' and
queries the related 'info.plist' file for string 'CFBundleShortVersionString'
via command line option 'defaults read'.";

  script_tag(name : "summary" , value : tag_summary);

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("gather-package-list.nasl");
  script_family("Product detection");
  script_mandatory_keys("ssh/login/osx_name");
  exit(0);
}


include("cpe.inc");
include("ssh_func.inc");
include("version_func.inc");
include("host_details.inc");

sock = ssh_login_or_reuse_connection();
if(!sock){
  exit(0);
}

if(!get_kb_item("ssh/login/osx_name")){
  close(sock);
  exit(0);
}

## Get the version of Mozilla Firefox
ffVer = chomp(ssh_cmd(socket:sock, cmd:"defaults read /Applications/" +
              "Firefox.app/Contents/Info CFBundleShortVersionString"));

if(!isnull(ffVer) && "does not exist" >!< ffVer)
{
  ffVer = eregmatch(pattern:"([0-9.]+)([a-zA-Z0-9]+)?", string:ffVer);
  if(ffVer[1] != NULL)
  {
    if(ffVer[2] != NULL){
      ffVer = ffVer[1] + "." + ffVer[2];
    }
    else {
      ffVer = ffVer[1];
    }
  }

  if(ffVer)
  {
 
    key_list = make_list("/Applications/Firefox.app/Contents/MacOS",
                    "/Applications/Firefox.app/Contents/Resources");
    ## Check for ESR version
    foreach dir (key_list)
    {
      esrFile = find_file(file_name:"update-settings.ini",file_path: dir, useregex:TRUE,
                       regexpar:"$", sock:sock);
      if(esrFile)
      {
        foreach binaryName (esrFile)
        {
          ## Checks if this is an ESR
          isFfEsr = get_bin_version(full_prog_name:"cat", sock:sock,
                                    version_argv:chomp(binaryName),
                                    ver_pattern:"mozilla-esr");
        }
      }
    }

    if(isFfEsr)
    {
      set_kb_item(name: "Mozilla/Firefox-ESR/MacOSX/Version", value:ffVer);
      set_kb_item( name:"Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Mac/Installed", value:TRUE );
      register_and_report_cpe( app:"Mozilla Firefox ESR", ver:ffVer, base:"cpe:/a:mozilla:firefox_esr:", expr:"^([0-9.]+)([a-zA-Z0-9]+)?", insloc:"/Applications/Firefox.app" );
    }
    else
    {
      set_kb_item(name: "Mozilla/Firefox/MacOSX/Version", value:ffVer);
      set_kb_item( name:"Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Mac/Installed", value:TRUE );
      register_and_report_cpe( app:"Mozilla Firefox", ver:ffVer, base:"cpe:/a:mozilla:firefox:", expr:"^([0-9.]+)([a-zA-Z0-9]+)?", insloc:"/Applications/Firefox.app" );
    }
  }
}


## Get the version of SeaMonkey
smVer = chomp(ssh_cmd(socket:sock, cmd:"defaults read /Applications/" +
              "SeaMonkey.app/Contents/Info CFBundleShortVersionString"));

if(!isnull(smVer) && "does not exist" >!< smVer)
{
  smVer = eregmatch(pattern:"([0-9.]+)([a-zA-Z0-9]+)?", string:smVer);
  if(smVer[1] != NULL)
  {
    if(smVer[2] != NULL){
      smVer = smVer[1] + "." + smVer[2];
    }
    else {
      smVer = smVer[1];
    }
  }

  set_kb_item(name: "SeaMonkey/MacOSX/Version", value:smVer);
  set_kb_item( name:"Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Mac/Installed", value:TRUE );
  register_and_report_cpe( app:"Mozilla SeaMonkey", ver:smVer, base:"cpe:/a:mozilla:seamonkey:", expr:"^([0-9.]+)", insloc:"/Applications/SeaMonkey.app" );
}

## Get the version of Thunderbird
tbVer = chomp(ssh_cmd(socket:sock, cmd:"defaults read /Applications/" +
              "Thunderbird.app/Contents/Info CFBundleShortVersionString"));

if(!isnull(tbVer) && "does not exist" >!< tbVer)
{
  tbVer = eregmatch(pattern:"([0-9.]+)([a-zA-Z0-9]+)?", string:tbVer);
  if(tbVer[1] != NULL)
  {
    if(tbVer[2] != NULL){
      tbVer = tbVer[1] + "." + tbVer[2];
    }
    else {
      tbVer = tbVer[1];
    }
  }

  if(tbVer)
  {
    dir = "/Applications/Thunderbird.app/Contents/MacOS";

    ## Check for ESR versions
    thuFile = find_file(file_name:"update-settings.ini",file_path: dir, useregex:TRUE,
                      regexpar:"$", sock:sock);
    if(thuFile)
    {
      foreach binaryName (thuFile)
      {
        ## Checks if this is an ESR
        isTbEsr = get_bin_version(full_prog_name:"cat", sock:sock,
                                  version_argv:chomp(binaryName),
                                  ver_pattern:"comm-esr");
      }
    }

    if(isTbEsr)
    {
      set_kb_item(name: "ThunderBird-ESR/MacOSX/Version", value:tbVer);
      set_kb_item( name:"Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Mac/Installed", value:TRUE );
      register_and_report_cpe( app:"Mozilla Thunderbird ESR", ver:tbVer, base:"cpe:/a:mozilla:thunderbird_esr:", expr:"^([0-9.]+)([a-zA-Z0-9]+)?", insloc:"/Applications/Thunderbird.app" );
    }
    else
    {
      set_kb_item(name: "ThunderBird/MacOSX/Version", value:tbVer);
      set_kb_item( name:"Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Mac/Installed", value:TRUE );
      register_and_report_cpe( app:"Mozilla Thunderbird", ver:tbVer, base:"cpe:/a:mozilla:thunderbird:", expr:"^([0-9.]+)([a-zA-Z0-9]+)?", insloc:"/Applications/Thunderbird.app" );
    }
  }
}

close(sock);
