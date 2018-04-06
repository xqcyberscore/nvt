###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_dangerous_activex_ctrl.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# Detection of Dangerous ActiveX Control
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
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

tag_summary = "This script will list all the vulnerable activex controls installed
  on the remote windows machine with references and cause.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900188");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_version("$Revision: 9350 $");
  script_cve_id("CVE-2008-5002", "CVE-2008-4919", "CVE-2008-4342",
                "CVE-2008-5232", "CVE-2008-5492");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-02-04 15:43:54 +0100 (Wed, 04 Feb 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_name("Detection of Dangerous ActiveX Control");
  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("General");
  script_dependencies("secpod_reg_enum.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}

include("smb_nt.inc");
include("secpod_activex.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

clsid = make_list("{3352B5B9-82E8-4FFD-9EB1-1A3E60056904}", "{BDF3E9D2-5F7A-4F4A-A914-7498C862EA6A}",
                  "{00989888-BB72-4E31-A7C6-5F819C24D2F7}", "{5EFE8CB1-D095-11D1-88FC-0080C859833B}",
                  "{C2FBBB5F-6FF7-4F6B-93A3-7EDB509AA938}", "{2646205B-878C-11D1-B07C-0000C040BCDB}",
                  "{433268D7-2CD4-43E6-AA24-2188672E7252}", "{0D1011B3-89C8-4F8E-8693-BB970E2E81E0}",
                  "{D22AC3EF-B7D8-11D5-A281-005056BF0101}", "{FFFB1D8B-88D6-4C91-BB62-378625E8C73E}",
                  "{765E6B09-6832-4738-BDBE-25F226BA2AB0}", "{A27AD582-5BE5-4C2D-82F0-48B24FE02040}",
                  "{E4463A35-7E7A-4621-8248-91307AFA8EAD}", "{87D1A6EF-8CBC-458A-84B5-0333562418CD}",
                  "{A4A435CF-3583-11D4-91BD-0048546A1450}", "{6ABC861A-31E7-4D91-B43B-D3C98F22A5C0}",
                  "{97852E80-5BE4-4F90-B24F-0947E44761A2}", "{136A9D1D-1F4B-43D4-8359-6F2382449255}",
                  "{EFD84954-6B46-42f4-81F3-94CE9A77052D}", "{0B40A54D-BEC3-4077-9A33-701BD6ACDEB2}",
                  "{9EB320CE-BE1D-4304-A081-4B4665414BEF}", "{E2F2B9D0-96B9-4B25-B90C-636ECB207D18}",
                  "{4B6015E7-3ABB-45DC-96B7-55A843751F28}", "{D94AAA2A-C415-42E3-82B6-49FAB4EBFFE9}",
                  "{E055C02E-6258-40FF-80A7-3BDA52FACAD7}", "{AA7F2000-EA05-489d-900C-3C7C0A5497A3}",
                  "{36DBC179-A19F-48F2-B16A-6A3E19B42A87}", "{E838FBB2-574D-4926-9C81-CCB15F3A3F53}",
                  "{06CC1B18-42FA-41B8-91A9-D3E3A848C7A8}", "{EC935945-F1FD-4EE4-9115-FB32CE93F34F}",
                  "{6B2455FD-3669-4555-8DF8-69FD5BC846F8}", "{D34F5D71-99E4-4D96-91CA-F4104F69B8AE}",
                  "{4E7BD74F-2B8D-469E-DFF7-EC6BF4D5FA7D}", "{5A9E5061-EB7F-45FE-BDE6-3B7FDC5CFF32}",
                  "{B18FDF1D-4FBB-411D-9C59-AAFA7D4998E0}", "{09B68AD9-FF66-3E63-636B-B693E62F6236}",
                  "{02478D38-C3F9-4efb-9B51-7695ECA15670}", "{706f3805-27d7-478d-80e5-e25d2bb030b3}",
                  "{B212D577-05B7-4963-911E-4A8588160DFA}", "{eee7178c-bbc3-4153-9dde-cd0e9ab1b5b6}",
                  "{1AE6D7D5-0C28-4DB6-9FD1-33B870A4C5F2}", "{53E10C2C-43B2-4657-BA29-AAE179E7D35C}",
                  "{327C3AF0-4EF6-4f8a-9A8D-685A4815D9F8}", "{3845CD5A-6FA0-3E0C-3980-000CD8DE3A31}",
                  "{6FAA7D12-F331-4B51-8D72-877A3CE20E84}");

refeList = make_list(
  "http://archives.neohapsis.com/archives/fulldisclosure/2008-07/0509.html",
  "http://securityresponse.symantec.com/avcenter/venc/data/dialer.instantaccess.html",
  "http://www.viruslist.com/en/viruses/encyclopedia?virusid=67936",
  "http://www.viruslist.com/en/viruses/encyclopedia?virusid=74565",
  "http://www.spywareguide.com/product_show.php?id=431",
  "http://www.spywareguide.com/product_show.php?id=860",
  "http://www3.ca.com/securityadvisor/pest/pest.aspx?id=453094115",
  "http://www.symantec.com/security_response/writeup.jsp?docid=2005-053116-0108-99",
  "http://www.spywareguide.com/product_show.php?id=458",
  "http://www.spywareguide.com/product_show.php?id=648",
  "http://www.kephyr.com/spywarescanner/library/mirartoolbar.winnb42/index.phtml",
  "http://www.trendmicro.com/vinfo/grayware/ve_graywareDetails.asp?GNAME=ADW_SUPERBAR.A",
  "http://www.kephyr.com/spywarescanner/library/relatedlinks.lbbho/index.phtml",
  "http://de.trendmicro-europe.com/enterprise/vinfo/encyclopedia.php?LYstr=VMAINDATA&vNav=3&VName=TROJ_WINSHOW.AF",
  "http://www.spywareguide.com/product_show.php?id=813",
  "http://www.symantec.com/security_response/print_writeup.jsp?docid=2003-080414-3713-99",
  "http://www3.ca.com/securityadvisor/pest/pest.aspx?id=453079049",
  "http://www.superantispyware.com/definition/halflemon/",
  "http://research.sunbelt-software.com/threatdisplay.aspx?name=Trojan-Downloader.Matcash&threatid=89006",
  "http://vil.nai.com/vil/Content/v_142599.htm",
  "http://vil.nai.com/vil/content/v_141822.htm",
  "http://vil.nai.com/vil/content/v_142672.htm",
  "http://vil.nai.com/vil/content/v_138384.htm",
  "http://vil.nai.com/vil/content/v_138384.htm",
  "http://vil.nai.com/vil/content/v_139523.htm",
  "http://vil.nai.com/vil/content/v_142381.htm",
  "http://vil.nai.com/vil/content/v_132034.htm",
  "http://vil.nai.com/vil/content/v_140376.htm",
  "http://vil.nai.com/vil/content/v_142395.htm",
  "http://vil.nai.com/vil/content/v_132847.htm",
  "http://vil.nai.com/vil/content/v_140856.htm",
  "http://vil.nai.com/vil/content/v_137381.htm",
  "http://vil.nai.com/vil/content/v_134309.htm",
  "http://vil.nai.com/vil/content/v_137508.htm",
  "http://vil.nai.com/vil/content/v_127690.htm",
  "http://www.ca.com/us/securityadvisor/pest/pest.aspx?id=453072526",
  "http://www.f-secure.com/v-descs/trojan-spy_w32_banker_cpv.shtml",
  "http://www.viruslist.com/en/viruses/encyclopedia?virusid=74127",
  "http://www.viruslist.com/en/viruses/encyclopedia?virusid=75772");

i = 0;
flag = 0;
actvxInfo = "";
foreach id (clsid)
{
  if(is_killbit_set(clsid:id) == 0)
  {
    actvxInfo = actvxInfo + "\n\nCLSID : " + id + "\nReference : " + refeList[i];
    flag = 1;
  }
  i++;
}

if(flag == 1){
  solution = string("Workaround: Set the killbit for the above CLSID(s).\n",
                    "Refer http://support.microsoft.com/kb/240797");
  security_message(data:string("The following clsid(s) ",
                              "were found on the remote host, which are ",
                              "related to dangerous ActiveX controls.",
                              actvxInfo, "\n\n", solution));
}
