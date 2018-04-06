###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_visualization_library_detect_win.nasl 9347 2018-04-06 06:58:53Z cfischer $
#
# Visualization Library Version Detection (Windows)
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
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
##############################################################################

tag_summary = "This script detects the installed version of Visualization
  Library and sets the result in KB.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800999");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 9347 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 08:58:53 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2010-03-18 15:44:57 +0100 (Thu, 18 Mar 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Visualization Library Version Detection (Windows)");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Service detection");
  script_dependencies("secpod_reg_enum.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("smb_nt.inc");
include("secpod_smb_func.inc");
include("cpe.inc");
include("host_details.inc");

## Constant values
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.800999";
SCRIPT_DESC = "Visualization Library Version Detection (Windows)";

## Check for Windows OS
if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

## Get Visualization Library installed path
exeFile = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion" ,
                          item:"ProgramFilesDir");
if(!exeFile){
  exit(0);
}

## Construct exe path
vlPath1 = exeFile + "\Visualization_Library_SDK-2009.08\include\vl";
vlPath2 = exeFile + "\Visualization_Library_SDK-2009.07\include\vl";

## Iterate over each path
foreach dir(make_list(vlPath1, vlPath2))
{
  ## Construct file path
  filePath = dir + "\version.hpp";
  if(isnull(filePath)){
      exit(0);
  }

  ## Get file contents
  share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:filePath);
  file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:filePath);
  verText = read_file(share:share, file:file, offset:0, count:500);

  if(verText)
  {
    ## Extract Versions
    mjVer = eregmatch(pattern:"VL_Major ([0-9]+)", string:verText, icase:1);
    mnVer = eregmatch(pattern:"VL_Minor ([0-9]+)", string:verText, icase:1);
    blVer = eregmatch(pattern:"VL_Build ([0-9]+)", string:verText, icase:1);

    if(mnVer[1] != NULL)
    {
      ## Construct Version
      vlVer = mjVer[1] + "." + mnVer[1] + "." + blVer[1];
      if(vlVer != NULL)
      {
        ## Set version into the KB
        set_kb_item(name:"VisualizationLibrary/Win/Ver", value:vlVer);
        log_message(data:"Visualization Library version " + vlVer +
                         " was detected on the host");
      
        ## build cpe and store it as host_detail
        cpe = build_cpe(value:vlVer, exp:"^([0-9.]+)", base:"cpe:/a:visualizationlibrary:visualization_library:");
        if(!isnull(cpe))
           register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

        exit(0);
       }
     }
  }
}
