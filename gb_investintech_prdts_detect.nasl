###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_investintech_prdts_detect.nasl 5372 2017-02-20 16:26:11Z cfi $
#
# Investintech Products Version Detection
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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

tag_summary = "This script finds the installed version of Investintech
  products and sets the result in KB.";

if(description)
{
  script_id(802501);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 5372 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"last_modification", value:"$Date: 2017-02-20 17:26:11 +0100 (Mon, 20 Feb 2017) $");
  script_tag(name:"creation_date", value:"2011-11-09 17:25:24 +0530 (Wed, 09 Nov 2011)");
  script_name("Investintech Products Version Detection");
  script_category(ACT_GATHER_INFO);
  script_tag(name: "qod_type", value: "executable_version");
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_reg_enum.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}

include("cpe.inc");
include("smb_nt.inc");
include("version_func.inc");
include("host_details.inc");
include("secpod_smb_func.inc");

## Constant values
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.802501";
SCRIPT_DESC = "Investintech Products Version Detection";

## functions for script
function register_cpe(tmpVers, tmpExpr, tmpBase){

   local_var cpe;
   ## build cpe and store it as host_detail
   cpe = build_cpe(value:tmpVers, exp:tmpExpr, base:tmpBase);
   if(!isnull(cpe))
      register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);
}

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
if(!registry_key_exists(key:key)){
  exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  prdtName = registry_get_sz(key:key + item, item:"DisplayName");

  ## Slim PDFReader
  if("SlimPDF Reader" >< prdtName)
  {
    ## Get the installed location
    pdfPath = registry_get_sz(key:key + item, item:"InstallLocation");
    if(!isnull(pdfPath))
    {
      ## Get the Version
      pdfVer = fetch_file_version(sysPath:pdfPath, file_name:"SlimPDF Reader.exe");
      if(pdfVer != NULL)
      {
        set_kb_item(name:"SlimPDF/Reader/Ver", value:pdfVer);
        log_message(data:"SlimPDF Reader version " + pdfVer +
                                         " was detected on the host");
        ## build cpe and store it as host_detail
        register_cpe(tmpVers:pdfVer, tmpExpr:"^([0-9.]+)",
                             tmpBase:"cpe:/a:investintech:slimpdf_reader:");
      }
    }
  }

  ## Able2Doc
  else if("Able2Doc" >< prdtName)
  {
    ## Get the version
    docVer = registry_get_sz(key:key + item, item:"DisplayVersion");
    if(docVer != NULL)
    {
      set_kb_item(name:"Able2Doc/Ver", value:docVer);
      log_message(data:"Able2Doc version " + docVer +
                                  " was detected on the host");

      ## build cpe and store it as host_detail
      register_cpe(tmpVers:docVer, tmpExpr:"^([0-9.]+)",
                             tmpBase:"cpe:/a:investintech:able2doc:");
    }
  }

  ## Able2Doc Professional
  else if("Able2Doc Professional" >< prdtName)
  {
    docVer = registry_get_sz(key:key + item, item:"DisplayVersion");
    if(docVer != NULL)
    {
      set_kb_item(name:"Able2Doc/Pro/Ver", value:docVer);
        log_message(data:"Able2Doc Professional version " + docVer +
                                         " was detected on the host");

      ## build cpe and store it as host_detail
      register_cpe(tmpVers:docVer, tmpExpr:"^([0-9.]+)",
                             tmpBase:"cpe:/a:investintech:able2doc:::professional:");
    }
  }

  ## Able2Extract
  else if(prdtName =~ "Able2Extract ([0-9.])+")
  {
    docVer = registry_get_sz(key:key + item, item:"DisplayVersion");
    if(docVer != NULL)
    {
      set_kb_item(name:"Able2Extract/Ver", value:docVer);
      log_message(data:"Able2Extract version " + docVer +
                                         " was detected on the host");

      ## build cpe and store it as host_detail
      register_cpe(tmpVers:docVer, tmpExpr:"^([0-9.]+)",
                             tmpBase:"cpe:/a:investintech:able2extract:");
    }
  }

  else if("Able2Extract PDF Server" >< prdtName)
  {
    serVer = registry_get_sz(key:key + item, item:"DisplayVersion");
    if(serVer != NULL)
    {
      set_kb_item(name:"Able2Extract/PDF/Server/Ver", value:serVer);
      log_message(data:"Able2Extract PDF Server version " + serVer +
                                         " was detected on the host");

      ## build cpe and store it as host_detail
      register_cpe(tmpVers:serVer, tmpExpr:"^([0-9.]+)",
                             tmpBase:"cpe:/a:investintech:able2extract_server:");
    }
  }
}
