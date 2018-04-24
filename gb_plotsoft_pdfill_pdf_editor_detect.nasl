###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_plotsoft_pdfill_pdf_editor_detect.nasl 9580 2018-04-24 08:44:20Z jschulte $
#
# PlotSoft PDFill PDF Editor Version Detection
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802178");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 9580 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-24 10:44:20 +0200 (Tue, 24 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-10-14 14:22:41 +0200 (Fri, 14 Oct 2011)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("PlotSoft PDFill PDF Editor Version Detection");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Service detection");
  script_dependencies("secpod_reg_enum.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_tag(name : "summary" , value : "This script detects the installed version of PlotSoft PDFill
  PDF Editor and sets the result in KB.");
  exit(0);
}


include("cpe.inc");
include("smb_nt.inc");
include("secpod_smb_func.inc");
include("host_details.inc");

## Constant values
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.802178";
SCRIPT_DESC = "PlotSoft PDFill PDF Editor Version Detection";

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

## Check if PlotSoft PDFill PDF Editor is installed
if(!registry_key_exists(key:"SOFTWARE\PlotSoft\PDFill")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
if(!registry_key_exists(key:key)){
  exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  pdfName = registry_get_sz(key:key + item, item:"DisplayName");

  ## Check for application name
  if("PDFill PDF Editor" >< pdfName)
  {
    ## Get the version
    pdfVer = registry_get_sz(key:key + item, item:"DisplayVersion");
    if(!isnull(pdfVer))
    {
      set_kb_item(name:"PlotSoft/PDFill/PDF/Editor/Ver", value:pdfVer);
      log_message(data:"PlotSoft PDFill PDF Editor version " + pdfVer +
                     " was detected on the host");

      ## build cpe and store it as host_detail
      cpe = build_cpe(value:pdfVer, exp:"^([0-9.]+)",
                                 base:"cpe:/a:plotsoft:pdfill_pdf_editor:");
      if(!isnull(cpe))
         register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID,
                                                          desc:SCRIPT_DESC);
      exit(0);
    }
  }
}
