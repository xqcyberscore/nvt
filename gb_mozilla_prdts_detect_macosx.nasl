###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mozilla_prdts_detect_macosx.nasl 6445 2017-06-27 12:31:06Z santu $
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.802179";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 6445 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-06-27 14:31:06 +0200 (Tue, 27 Jun 2017) $");
  script_tag(name:"creation_date", value:"2011-10-14 14:22:41 +0200 (Fri, 14 Oct 2011)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Mozilla Products Version Detection (Mac OS X)");

  tag_summary =
"Detection of installed version of Mozilla Firefox on Windows.

The script logs in via ssh, searches for folder Mozilla products '.app' and
queries the related 'info.plist' file for string 'CFBundleShortVersionString'
via command line option 'defaults read'.";


  script_tag(name : "summary" , value : tag_summary);

  script_summary("Detection of installed version of Mozilla Product on Max OS X");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("gather-package-list.nasl");
  script_family("Product detection");
  script_mandatory_keys("login/SSH/success");
  exit(0);
}


include("cpe.inc");
include("ssh_func.inc");
include("version_func.inc");
include("host_details.inc");

## start script
## Checking OS
sock = ssh_login_or_reuse_connection();
if(!sock){
  exit(0);
}

## Checking for Mac OS X
if(!get_kb_item("ssh/login/osx_name"))
{
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
          ## Get the version
          esrVer = get_bin_version(full_prog_name:"cat", sock:sock,
                                   version_argv:chomp(binaryName),
                                   ver_pattern:"mozilla-esr");
        }
      }
    }

    ## Set the version in KB and CPE
    if(esrVer)
    {
      set_kb_item(name: "Mozilla/Firefox-ESR/MacOSX/Version", value:ffVer);

      ## Build CPE
      cpe = build_cpe(value:ffVer, exp:"^([0-9.]+)([a-zA-Z0-9]+)?", base:"cpe:/a:mozilla:firefox_esr:");
      if(isnull(cpe))
        cpe = "cpe:/a:mozilla:firefox_esr";

      appName = 'Mozilla Firefox ESR';
    }
    else
    {
      set_kb_item(name: "Mozilla/Firefox/MacOSX/Version", value:ffVer);
      replace_kb_item( name:"Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Mac/Installed", value:TRUE ); 
      ## Build CPE
      cpe = build_cpe(value:ffVer, exp:"^([0-9.]+)([a-zA-Z0-9]+)?", base:"cpe:/a:mozilla:firefox:");
      if(isnull(cpe))
        cpe = 'cpe:/a:mozilla:firefox';

      appName = 'Mozilla Firefox';
    }

    ## Register Product and Build Report
    build_report(app: appName, ver: ffVer, cpe: cpe, insloc: "/Applications/Firefox.app");
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

  dir = "/Applications/SeaMonkey.app";

  ## Set the version in KB
  set_kb_item(name: "SeaMonkey/MacOSX/Version", value:smVer);
  replace_kb_item( name:"Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Mac/Installed", value:TRUE );
  ## build cpe
  cpe = build_cpe(value:smVer, exp:"^([0-9.]+)", base:"cpe:/a:mozilla:seamonkey:");
  if(isnull(cpe))
    cpe = 'cpe:/a:mozilla:seamonkey';

  ## Register Product and Build Report
  build_report(app: "Mozilla SeaMonkey", ver: smVer, cpe: cpe, insloc: "/Applications/SeaMonkey.app");
}


## Get the version of ThunderBird
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
        ## Get the version
        thuVer = get_bin_version(full_prog_name:"cat", sock:sock,
                                 version_argv:chomp(binaryName),
                                 ver_pattern:"comm-esr");
      }
    }

    ## Set the version in KB and CPE
    if(thuVer)
    {
      set_kb_item(name: "ThunderBird-ESR/MacOSX/Version", value:tbVer);
      replace_kb_item( name:"Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Mac/Installed", value:TRUE );

      ## build cpe
      cpe = build_cpe(value:tbVer, exp:"^([0-9.]+)([a-zA-Z0-9]+)?", base:"cpe:/a:mozilla:thunderbird_esr:");
      if(isnull(cpe))
        cpe = "cpe:/a:mozilla:thunderbird_esr";

      appName = 'Mozilla ThunderBird ESR';
    }
    else
    {
      set_kb_item(name: "ThunderBird/MacOSX/Version", value:tbVer);

      ## build cpe
      cpe = build_cpe(value:tbVer, exp:"^([0-9.]+)([a-zA-Z0-9]+)?", base:"cpe:/a:mozilla:thunderbird:");
      if(isnull(cpe))
        cpe = "cpe:/a:mozilla:thunderbird";

      appName = 'Mozilla ThunderBird';
    }

    ## Register Product and Build Report
    build_report(app: appName, ver: tbVer, cpe: cpe, insloc: "/Applications/Thunderbird.app");
  }
}

## Close Socket
close(sock);
