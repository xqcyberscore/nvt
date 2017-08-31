###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_symantec_prdts_detect.nasl 6517 2017-07-04 13:34:20Z cfischer $
#
# Symantec Product(s) Version Detection
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Update By: Antu Sanadi <santu@secpod.com> on 2010-02-25
# Updated to detect and set KB for EndPoint Protection IM Manager
#
# Update By: Sooraj KS <kssooraj@secpod.com> on 2011-02-01
# Updated to detect Symantec AntiVirus Corporate Edition
#
# Update By:  Rachana Shetty <srachana@secpod.com> on 2012-03-03
# Updated to detect Symantec Norton AntiVirus and according to CR-57
# On 2012-11-23 to detect SEPSBE
#
# Updated By: Shakeel <bshakeel@secpod.com> on 2014-09-02
# To support 32 and 64 bit.
#
# Copyright:
# Copyright (C) 2009 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.900332");
  script_version("$Revision: 6517 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-07-04 15:34:20 +0200 (Tue, 04 Jul 2017) $");
  script_tag(name:"creation_date", value:"2009-03-30 15:53:34 +0200 (Mon, 30 Mar 2009)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Symantec Product(s) Version Detection");

  script_tag(name: "summary" , value: "Detection of installed version of
  Symantec Product(s).

  The script logs in via smb, searches for Symantec Product(s) in the registry
  and gets the version from registry.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Product detection");
  script_dependencies("secpod_reg_enum.nasl", "smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  script_require_ports(139, 445);
  exit(0);
}


include("smb_nt.inc");
include("secpod_smb_func.inc");
include("cpe.inc");
include("host_details.inc");
include("version_func.inc");


## Variable Initialization
os_arch = "";
key = "";
nisVer = "";
insloc = "";
symkey = "";
symantecName = "";
navVer = "";
navPath = "";
nisPath = "";
pcawVer = "";
pcawVer = "";
esmVer = "";
esmPath = "";
savceVer = "";
savcePath = "";
imVer = "";
imPath = "";

## Get OS Architecture
os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch){
  exit(-1);
}

## Check for 32 bit platform
if("x86" >< os_arch){
  key_list = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\");
  key_list2 = make_list("SOFTWARE\Symantec\Symantec Endpoint Protection\SEPM");
}

## Check for 64 bit platform, only 32-bit app is available
else if("x64" >< os_arch){
  key_list =  make_list("SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\");
  key_list2  = make_list("SOFTWARE\Wow6432Node\Symantec\Symantec Endpoint Protection\SEPM");
}

foreach symkey(key_list)
{
  foreach item(registry_enum_keys(key:symkey))
  {
    symantecName = registry_get_sz(key:symkey + item, item:"DisplayName");

    ##Check for Norton Antivirus
    if("Norton AntiVirus" >< symantecName)
    {
      navVer = registry_get_sz(key:symkey + item, item:"DisplayVersion");
      if(navVer)
      {
        replace_kb_item(name:"Symantec_or_Norton/Products/Win/Installed", value:TRUE);
        set_kb_item(name:"Symantec/Norton-AV/Ver", value:navVer);

        ## Get Install Location
        navPath = registry_get_sz(key: symkey + item, item:"InstallLocation");
        if(! navPath){
          navPath = "Could not find the install Location from registry";
        }

        ## Build CPE
        cpe = build_cpe(value:navVer, exp:"^([0-9.]+)", base:"cpe:/a:symantec:norton_antivirus:");
        if(isnull(cpe))
          cpe = 'cpe:/a:symantec:norton_antivirus';

        build_report(app:symantecName, ver:navVer, cpe:cpe, insloc:navPath, concluded:navVer);
      }
    }

    ## Check for Norton Internet Security
    if("Norton Internet Security" >< symantecName)
    {
      nisVer = registry_get_sz(key:symkey + item, item:"DisplayVersion");
      if(nisVer)
      {
        replace_kb_item(name:"Symantec_or_Norton/Products/Win/Installed", value:TRUE);
        set_kb_item(name:"Norton/InetSec/Ver", value:nisVer);

        ## Get Install Location
        nisPath = registry_get_sz(key:symkey + item, item:"InstallLocation");
        if(! nisPath){
          nisPath = "Could not find the install Location from registry";
        }

        ## Build CPE
        cpe = build_cpe(value:nisVer, exp:"^([0-9.]+)", base:"cpe:/a:symantec:norton_internet_security:");
        if(isnull(cpe))
          cpe = 'cpe:/a:symantec:norton_internet_security';

        build_report(app:symantecName, ver:nisVer, cpe:cpe, insloc:nisPath, concluded:nisVer);
      }
    }

    ##Check for Symantec pcAnywhere, Product reaced EOL(End of Life)
    if("Symantec pcAnywhere" >< symantecName)
    {
      pcawVer = registry_get_sz(key:symkey + item, item:"DisplayVersion");
      if(pcawVer)
      {
        replace_kb_item(name:"Symantec_or_Norton/Products/Win/Installed", value:TRUE);
        set_kb_item(name:"Symantec/pcAnywhere/Ver", value:pcawVer);

        ## Get Install Location
        pcawPath = registry_get_sz(key:symkey + item, item:"InstallLocation");
        if(! pcawPath){
          pcawPath = "Could not find the install Location from registry";
        }

        ## Build CPE
        cpe = build_cpe(value: pcawVer, exp:"^([0-9.]+)", base:"cpe:/a:symantec:pcanywhere:");
        if(isnull(cpe))
          cpe = 'cpe:/a:symantec:pcanywhere';

        build_report(app:symantecName, ver:pcawVer, cpe:cpe, insloc:pcawPath, concluded:pcawVer);
      }
    }

    ##Check for Enterprise Security Manager
    if("Enterprise Security Manager" >< symantecName)
    {
      esmVer = registry_get_sz(key:symkey + item, item:"DisplayVersion");
      if(esmVer)
      {
        replace_kb_item(name:"Symantec_or_Norton/Products/Win/Installed", value:TRUE);
        set_kb_item(name:"Symantec/ESM/Ver", value:esmVer);
        set_kb_item(name:"Symantec/ESM/Component", value:symantecName);

        ## Get Install Location
        esmPath = registry_get_sz(key:symkey + item, item:"InstallLocation");
        if(! esmPath){
          esmPath = "Could not find the install Location from registry";
        }

        set_kb_item(name:"Symantec/ESM/Path", value:esmPath);

        ## Build CPE
        cpe = build_cpe(value:esmVer, exp:"^([0-9.]+)", base:"cpe:/a:symantec:enterprise_security_manager:");
        if(isnull(cpe))
          cpe = 'cpe:/a:symantec:enterprise_security_manager';

        build_report(app:symantecName, ver:esmVer, cpe:cpe, insloc:esmPath, concluded:esmVer);
      }
    }

    ## Symantec AntiVirus Corporate Edition, this product is Discontinued.
    if("Symantec AntiVirus" >< symantecName)
    {
      savceVer = registry_get_sz(key:symkey + item, item:"DisplayVersion");
      if(savceVer)
      {
        replace_kb_item(name:"Symantec_or_Norton/Products/Win/Installed", value:TRUE);
        set_kb_item(name:"Symantec/SAVCE/Ver", value:savceVer);

        ## Get Install Location
        savcePath = registry_get_sz(key:symkey + item, item:"InstallLocation");
        if(! savcePath){
          savcePath = "Could not find the install Location from registry";
        }

        ## Build CPE
        cpe = build_cpe(value: savceVer, exp:"^([0-9.]+)", base:"cpe:/a:symantec:antivirus:");
        if(isnull(cpe))
          cpe = 'cpe:/a:symantec:antivirus';

        build_report(app:symantecName, ver:savceVer, cpe:cpe, insloc:savcePath, concluded:savceVer);
      }
    }

    ## IMManager- this product is Discontinued
    if("IMManager" >< symantecName)
    {
      imPath = registry_get_sz(key:symkey + item, item:"InstallSource");
      if(imPath)
      {
        imPath = imPath - "\temp";
        imVer = fetch_file_version(sysPath:imPath, file_name:"IMLogicAdminService.exe");

        if(imVer)
        {
          replace_kb_item(name:"Symantec_or_Norton/Products/Win/Installed", value:TRUE);
          set_kb_item(name:"Symantec/IM/Manager", value:imVer);

          ## Build CPE
          cpe = build_cpe(value: imVer, exp:"^([0-9.]+)", base:"cpe:/a:symantec:im_manager:");
          if(isnull(cpe))
            cpe = 'cpe:/a:symantec:im_manager';

          build_report(app:symantecName, ver:imVer, cpe:cpe, insloc:imPath, concluded:imVer);
        }
      }
    }
  }
}

## Check for Symantec Endpoint Protection
foreach symkey(key_list2)
{
  if(registry_key_exists(key:symkey))
  {
    # Setting KB for Endpoint Protection
    nisVer = registry_get_sz(key:symkey, item:"Version");
    if(nisVer)
    {
      replace_kb_item(name:"Symantec_or_Norton/Products/Win/Installed", value:TRUE);
      set_kb_item(name:"Symantec/Endpoint/Protection", value:nisVer);

      ## Get Install Location
      nisPath = registry_get_sz(key:symkey + item, item:"TargetDir");
      if(! nisPath){
        nisPath = "Could not find the install Location from registry";
      }

      ## For Symantec Endpoint Protection Small Business Edition
      ## Chekc product Type sepsb (Symantec Endpoint Protection Small Businees)

      nisType = registry_get_sz(key:symkey, item:"ProductType");
      if(nisType && "sepsb" >< nisType)
      {
        ## Set kb for product type
        set_kb_item(name:"Symantec/SEP/SmallBusiness", value:nisType);

        ## Build CPE
        cpe = build_cpe(value:nisVer, exp:"^([0-9.]+)", base:"cpe:/a:symantec:endpoint_protection:"
                                     + nisVer + ":small_business");
      }
      else{
        ## Build CPE
        cpe = build_cpe(value: nisVer, exp:"^([0-9.]+)", base:"cpe:/a:symantec:endpoint_protection:");
      }

      if(isnull(cpe))
        cpe = 'cpe:/a:symantec:endpoint_protection';

      build_report(app:"Symantec Endpoint Protection", ver:nisVer, cpe:cpe, insloc:nisPath, concluded:nisVer);

    }
  }
}
