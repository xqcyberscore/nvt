###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_firefox_detect_win.nasl 9887 2018-05-17 13:35:46Z cfischer $
#
# Mozilla Firefox Version Detection (Windows)
#
# Authors:
# Chandan S <schandan@secpod.com>
#
# Updated By: Madhuri D <dmadhuri@secpod.com> on 2010-09-17
#    - To detect beta versions
#
# Update By:  Rachana Shetty <srachana@secpod.com> on 2012-11-27
# Updated to detect Firefox ESR version and according to CR-57
#
# Update By:  Thanga Prakash S <tprakash@secpod.com> on 2013-09-23
# According to new style script_tags and Fixed issue in identifying ESR.
#
# Updated By: Shakeel <bshakeel@secpod.com> on 2014-06-24
# According to CR57 and to support 32 and 64 bit.
#
# Updated By: Thanga Prakash S <tprakash@secpod.com> on 2015-01-07
# Updated to detect 32bit version on 64bit OS
#
# Copyright:
# Copyright (C) 2008 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.800014");
  script_version("$Revision: 9887 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-05-17 15:35:46 +0200 (Thu, 17 May 2018) $");
  script_tag(name:"creation_date", value:"2008-10-06 13:07:14 +0200 (Mon, 06 Oct 2008)");
  script_name("Mozilla Firefox Version Detection (Windows)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("secpod_reg_enum.nasl");
  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name:"summary", value:"Detection of installed version of Mozilla Firefox on Windows.

  The script logs in via smb, searches for Mozilla Firefox in the registry
  and gets the version from registry.");

  script_tag(name:"qod_type", value:"executable_version");

  exit(0);
}

include("smb_nt.inc");
include("secpod_smb_func.inc");
include("cpe.inc");
include("host_details.inc");
include("version_func.inc");

checkduplicate = ""; # Keep in here to make openvas-nasl-lint happy...

os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch){
  exit(0);
}

if("x86" >< os_arch){
  key_list = make_list("SOFTWARE\Mozilla",
                       "SOFTWARE\mozilla.org");
  key_list2 = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion");

} else if("x64" >< os_arch){
  key_list = make_list("SOFTWARE\Mozilla",
                       "SOFTWARE\mozilla.org",
                       "SOFTWARE\Wow6432Node\Mozilla",
                       "SOFTWARE\Wow6432Node\mozilla.org");

   key_list2 = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion",
                         "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion");
}

if(isnull(key_list && key_list2)){
  exit(0);
}

if(!registry_key_exists(key:"SOFTWARE\Mozilla")){
  if(!registry_key_exists(key:"SOFTWARE\mozilla.org")){
    if(!registry_key_exists(key:"SOFTWARE\Wow6432Node\Mozilla")){
      if(!registry_key_exists(key:"SOFTWARE\Wow6432Node\mozilla.org")){
        exit(0);
      }
    }
  }
}

foreach key(key_list){

  ##Clear Flag
  ESR = FALSE;

  # Check for Firefox browser
  foxVer = registry_get_sz(key:key + "\Mozilla Firefox", item:"CurrentVersion");
  if(!foxVer){
    # 32bit version on 64bit os key is different
    foxVer = registry_get_sz(key:key + "\Mozilla", item:"CurrentVersion");
  }
  ##For Case version is coming as 45.0.1 (x86 en-GB) and only 45.0.1, giving
  ## two messages for same version
  if(foxVer =~ "([0-9.]+).*[a-zA-Z]."){
    foxVerlist = eregmatch(string:foxVer, pattern:"([0-9.]+)");
    if(foxVerlist){
      foxVer = foxVerlist[1];
    }
  }

  # TODO: Fix the detection instead of ignoring e.g. the same
  # version of 32bit and 64bit apps are installed...
  ##If same firefox version has been detected already continue
  if(foxVer + ", " >< checkduplicate){
    continue;
  }

  if(foxVer) {
    # Special case for Firefox 1.5 (Get the version from file)
    if(foxVer =~ "^1\.5") {
      foreach key(key_list2) {
        exeFile  = registry_get_sz(key:key + "\Uninstall\Mozilla Firefox (1.5)", item:"InstallLocation");
        location = exeFile;
        if(location) {
          foxVer = fetch_file_version(sysPath:location, file_name:"firefox.exe");
        } else {
          foxVer = eregmatch(pattern:"([0-9.]+)([0-9a-zA-Z]*)", string:foxVer);
          if(foxVer[1] && foxVer[2])
            foxVer[0] = foxVer[1] + "." + foxVer[2];

          foxVer = foxVer[0];
        }
      }
    }

    foreach key(key_list2) {
      path = registry_get_sz(key:key, item:"ProgramFilesDir");
      if(!path) exit(0); # TBD: Really exit and not just a continue?
      appPath = path + "\Mozilla Firefox";
      foxVer_check = fetch_file_version(sysPath:appPath, file_name:"firefox.exe");
      ## foxVer_check =50.1.0.6186, foxVer=50.1.0
      if(foxVer >< foxVer_check){
        location = appPath;
        break;
      } else {
        location = NULL; # nb: This makes sure we're not registering a non-existent version below
        continue;
      }
    }

    if(!location) continue;

    # Check for ESR installation
    if(!ESR){
      ##Check contents of application.ini
      exePath = appPath + "\application.ini";
      share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:exePath);
      file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:exePath);
      ## Read the content of .txt file
      readmeText = read_file(share:share, file:file, offset:0, count:3000);
      if(readmeText =~ "mozilla-esr"){
        foxVer_check = eregmatch(pattern:"version=([0-9.]+)", string:readmeText);
        if(foxVer_check[1] == foxVer){
          ESR = TRUE;
        }
      }
    }

    if(!ESR){
      ##Check contents of platform.ini
      exePath = appPath + "\platform.ini";
      share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:exePath);
      file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:exePath);

      ## Read the content of .txt file
      readmeText = read_file(share:share, file:file, offset:0, count:3000);
      if(readmeText =~ "mozilla-esr"){
        foxVer_check = eregmatch(pattern:"Milestone=([0-9.]+)", string:readmeText);
        if(foxVer_check[1] == foxVer){
          ESR = TRUE;
        }
      }
    }

    if(!ESR){
      ##Check for ESR in update-settings.ini
      exePath = appPath + "\update-settings.ini";

      share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:exePath);
      file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:exePath);
      ## Read the content of .ini file
      readmeText = read_file(share:share, file:file, offset:0, count:3000);
      if(readmeText =~ "mozilla-esr"){
        ##Not Reliable option, If two Firefox versions are there (one ESR and One Main) and main
        ## firefox is detected, and update-settings.ini of another installed ESR firefox has mozilla-esr
        ## Main Firefox is detected as ESR. Putting it as last option, some old setups might
        ## have this only as indication of esr-version. Latest firefox versions working fine as
        ## control never falls to this block. Tested on various installations
        ESR = TRUE;
      }
    }

    if(ESR && location){

      set_kb_item(name:"Firefox-ESR/Win/Ver", value:foxVer);
      set_kb_item(name:"Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Installed", value:TRUE);

      cpe = build_cpe(value:foxVer, exp:"^([0-9.]+)([0-9a-zA-Z]*)", base:"cpe:/a:mozilla:firefox_esr:");
      if(isnull(cpe))
        cpe = 'cpe:/a:mozilla:firefox_esr';

      ## Register for 64 bit app on 64 bit OS once again
      if("64" >< os_arch && "Wow6432Node" >!< key){
        set_kb_item(name:"Firefox-ESR64/Win/Ver", value:foxVer);
        cpe = build_cpe(value:foxVer, exp:"^([0-9.]+)([0-9a-zA-Z]*)", base:"cpe:/a:mozilla:firefox_esr:x64:");
        if(isnull(cpe))
          cpe = "cpe:/a:mozilla:firefox_esr:x64";
      }
      appName = 'Mozilla Firefox ESR';
    } else if(location) {

      set_kb_item(name:"Firefox/Win/Ver", value:foxVer);
      set_kb_item(name:"Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Installed", value:TRUE);
      set_kb_item(name:"Firefox/Linux_or_Win/installed", value:TRUE);

      cpe = build_cpe(value:foxVer, exp:"^([0-9.]+)([0-9a-zA-Z]*)", base:"cpe:/a:mozilla:firefox:");
      if(isnull(cpe))
        cpe = 'cpe:/a:mozilla:firefox';

      ## Register for 64 bit app on 64 bit OS once again
      if("64" >< os_arch && "Wow6432Node" >!< key){
        set_kb_item(name:"Firefox64/Win/Ver", value:foxVer);
        cpe = build_cpe(value:foxVer, exp:"^([0-9.]+)([0-9a-zA-Z]*)", base:"cpe:/a:mozilla:firefox:x64:");
        if(isnull(cpe))
          cpe = "cpe:/a:mozilla:firefox:x64";
      }
      appName = 'Mozilla Firefox';
    }

    ##To detect only Firefox versions for which location is available
    ##Old versions removed still keep registry entries but location is not available for them
    if(location){
      ##Assign detected version value to checkduplicate so as to check in next loop iteration
      checkduplicate += foxVer + ", ";
      # Used in gb_firefox_detect_portable_win.nasl to detect doubled detections
      set_kb_item(name:"Firefox/Win/InstallLocations", value:tolower(location));
      register_product(cpe:cpe, location:location);
      log_message(port:0, data:build_detection_report(app:appName, version:foxVer, install:location, cpe:cpe, concluded:foxVer));
    }
  }
}
