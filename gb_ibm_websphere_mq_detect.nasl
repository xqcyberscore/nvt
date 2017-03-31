###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_websphere_mq_detect.nasl 5040 2017-01-19 14:01:58Z cfi $
#
# IBM WebSphere MQ Version Detection (Windows)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.805546");
  script_version("$Revision: 5040 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-01-19 15:01:58 +0100 (Thu, 19 Jan 2017) $");
  script_tag(name:"creation_date", value:"2015-05-06 11:01:01 +0530 (Wed, 06 May 2015)");
  script_name("IBM WebSphere MQ Version Detection (Windows)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("secpod_reg_enum.nasl", "smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  script_require_ports(139, 445);

  script_tag(name:"summary", value:"Detection of installed version of
  IBM WebSphere MQ.

  The script logs in via smb, searches for 'IBM WebSphere MQ'
  in the registry and gets the version from registry.");

  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

## variable Initialization
os_arch = "";
key = "";
mqPath = "";
mqVer = "";
mqName = "";

include("smb_nt.inc");
include("secpod_smb_func.inc");
include("cpe.inc");
include("host_details.inc");
include("version_func.inc");


## Get OS Architecture
os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch){
  exit(0);
}

## Check for 32 bit platform
if("x86" >< os_arch){
  key_list = make_list("SOFTWARE\IBM\WebSphere MQ\Installation\Installation1");
}

## Check for 64 bit platform
else if("x64" >< os_arch)
{
  key_list =  make_list("SOFTWARE\IBM\WebSphere MQ\Installation\Installation1",
                        "SOFTWARE\Wow6432Node\IBM\WebSphere MQ\Installation\Installation1");
}

foreach key( key_list ) {

  foreach item( registry_enum_keys( key:key ) )
  {
    ##Get application name
    mqName = registry_get_sz(key:key, item:"ProgramFolder");
    #### Confirm Application
    if("IBM WebSphere MQ" >< mqName)
    {
      mqVer = registry_get_sz(key:key, item:"BuildDate");
      mqVer = eregmatch(pattern:"version ([0-9.]+)", string:mqVer);
      if(mqVer[1])
      {
        mqVer = mqVer[1];

        mqPath = registry_get_sz(key:key, item:"FilePath");
        if(!mqPath){
          mqPath = "Couldn find the install location from registry";
      }

      set_kb_item(name:"IBM/Websphere/MQ/Win/Ver", value:mqVer);

      ## build cpe and store it as host_detail
      cpe = build_cpe(value:mqVer, exp:"^([0-9.]+)", base:"cpe:/a:ibm:websphere_mq:");
      if(isnull(cpe))
        cpe = "cpe:/a:ibm:websphere_mq";

      ## Register for 64 bit app on 64 bit OS once again
      if("64" >< os_arch)
      {
        set_kb_item(name:"IBM/Websphere/MQ/Win64/Ver", value:mqVer);

        ## Build CPE
        cpe = build_cpe(value:mqVer, exp:"^([0-9.]+)", base:"cpe:/a:ibm:websphere_mq:x64:");

        if(isnull(cpe))
          cpe = "cpe:/a:ibm:websphere_mq:x64";
      }
      ##register cpe
      register_product(cpe:cpe, location:mqPath);
      log_message(data: build_detection_report(app: mqName,
                                               version: mqVer,
                                               install: mqPath,
                                               cpe: cpe,
                                               concluded: mqVer));
      exit(0);
      }
    }
  }
}
