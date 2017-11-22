###############################################################################
# OpenVAS Vulnerability Test
# $Id: compliance_tests.nasl 7850 2017-11-21 14:31:39Z emoss $
#
# Compliance Tests
#
# Authors:
# Michael Wiegand <michael.wiegand@intevation.de>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_summary = "This script controls various compliance tests like IT-Grundschutz.";

if(description)
{
  script_id(95888);
  script_version("$Revision: 7850 $");
  script_tag(name:"last_modification", value:"$Date: 2017-11-21 15:31:39 +0100 (Tue, 21 Nov 2017) $");
  script_tag(name:"creation_date", value:"2010-04-27 10:02:59 +0200 (Tue, 27 Apr 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Compliance Tests");
  script_category(ACT_SETTINGS);
  script_tag(name:"qod_type", value:"general_note");
  script_copyright("Copyright (c) 2009-2015 Greenbone Networks GmbH");
  script_family("Compliance");

  script_add_preference(name:"Launch IT-Grundschutz (10. EL)", type:"checkbox", value:"no");
  script_add_preference(name:"Launch IT-Grundschutz (11. EL)", type:"checkbox", value:"no");
  script_add_preference(name:"Launch IT-Grundschutz (12. EL)", type:"checkbox", value:"no");
  script_add_preference(name:"Launch IT-Grundschutz (13. EL)", type:"checkbox", value:"no");
  script_add_preference(name:"Launch latest IT-Grundschutz version", type:"checkbox", value:"no");
  script_add_preference(name:"Verbose IT-Grundschutz results", type:"checkbox", value:"no");
  script_add_preference(name:"Launch PCI-DSS (Version 2.0)", type:"checkbox", value:"no");
  script_add_preference(name:"Launch latest PCI-DSS version", type:"checkbox", value:"no");
  script_add_preference(name:"Verbose PCI-DSS results", type:"checkbox", value:"no");
  script_add_preference(name:"PCI-DSS Berichtsprache/Report Language", type:"radio", value:"Deutsch;English");
  script_add_preference(name:"Testuser Common Name", type:"entry", value:"CN");
  script_add_preference(name:"Testuser Organization Unit", type:"entry", value:"OU");
  script_add_preference(name:"Windows Domaenenfunktionsmodus", type:"radio", value:"Unbekannt;Windows 2000 gemischt und Windows 2000 pur;Windows Server 2003 Interim;Windows Server 2003;Windows Server 2008;Windows Server 2008 R2");

  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}

# Set KB item if IT-Grundschutz is enabled
launch_gshb_10 = script_get_preference("Launch IT-Grundschutz (10. EL)");
if (launch_gshb_10 == "yes") {
  set_kb_item(name: "Compliance/Launch/GSHB-10", value: TRUE);
  set_kb_item(name: "Compliance/Launch/GSHB", value: TRUE);
}
launch_gshb_11 = script_get_preference("Launch IT-Grundschutz (11. EL)");
if (launch_gshb_11 == "yes") {
  set_kb_item(name: "Compliance/Launch/GSHB-11", value: TRUE);
  set_kb_item(name: "Compliance/Launch/GSHB", value: TRUE);
}
launch_gshb_12 = script_get_preference("Launch IT-Grundschutz (12. EL)");
if (launch_gshb_12 == "yes") {
  set_kb_item(name: "Compliance/Launch/GSHB-12", value: TRUE);
  set_kb_item(name: "Compliance/Launch/GSHB", value: TRUE);
}
launch_gshb_13 = script_get_preference("Launch IT-Grundschutz (13. EL)");
if (launch_gshb_13 == "yes") {
  set_kb_item(name: "Compliance/Launch/GSHB-13", value: TRUE);
  set_kb_item(name: "Compliance/Launch/GSHB", value: TRUE);
}
launch_gshb_14 = script_get_preference("Launch latest IT-Grundschutz version");
if (launch_gshb_14 == "yes") {
  set_kb_item(name: "Compliance/Launch/GSHB-14", value: TRUE);
  set_kb_item(name: "Compliance/Launch/GSHB", value: TRUE);
}
# Set KB item if IT-Grundschutz silence is requested
verbose_gshb = script_get_preference("Verbose IT-Grundschutz results");
if (verbose_gshb == "no") {
  set_kb_item(name: "GSHB-10/silence", value: "Wahr");
  set_kb_item(name: "GSHB-11/silence", value: "Wahr");
  set_kb_item(name: "GSHB-12/silence", value: "Wahr");
  set_kb_item(name: "GSHB-13/silence", value: "Wahr");
  set_kb_item(name: "GSHB/silence", value: "Wahr");
}

# Set KB item if PCI-DSS 2.0 is enabled
launch_pci_dss = script_get_preference("Launch PCI-DSS (Version 2.0)");
if (launch_pci_dss == "yes") {
  set_kb_item(name: "Compliance/Launch/PCI-DSS_2.0", value: TRUE);
  set_kb_item(name: "Compliance/Launch/GSHB", value: TRUE);
}
# Set KB item if latest PCI-DSS is enabled
launch_pci_dss = script_get_preference("Launch latest PCI-DSS version");
if (launch_pci_dss == "yes") {
  set_kb_item(name: "Compliance/Launch/PCI-DSS", value: TRUE);
  set_kb_item(name: "Compliance/Launch/GSHB", value: TRUE);
}
# Set KB item with PCI-DSS Report language
lang_pci_dss = script_get_preference("PCI-DSS Berichtsprache/Report Language");
if (lang_pci_dss == "Deutsch")  set_kb_item(name: "PCI-DSS/lang", value: "ger");
else if (lang_pci_dss == "English")  set_kb_item(name: "PCI-DSS/lang", value: "eng");
else set_kb_item(name: "PCI-DSS/lang", value: "eng");

# Set KB item if PCI-DSS silence is requested
verbose_pci_dss = script_get_preference("Verbose PCI-DSS results");
if (verbose_pci_dss == "no") {
  set_kb_item(name: "PCI-DSS/silence", value: "Wahr");
}

CN = script_get_preference("Testuser Common Name");
OU = script_get_preference("Testuser Organization Unit");
DomFunkMod = script_get_preference("Windows Domaenenfunktionsmodus");

if (DomFunkMod == "Unbekannt")DomFunk = "none";
else if (DomFunkMod == "Windows 2000 gemischt und Windows 2000 pur")DomFunk = "0";
else if (DomFunkMod == "Windows Server 2003 Interim")DomFunk = "1";
else if (DomFunkMod == "Windows Server 2003")DomFunk = "2";
else if (DomFunkMod == "Windows Server 2008")DomFunk = "3";
else if (DomFunkMod == "Windows Server 2008 R2")DomFunk = "4";
else if (!DomFunk)DomFunk = "none";

set_kb_item(name:"GSHB/CN", value:CN);
set_kb_item(name:"GSHB/OU", value:OU);
set_kb_item(name:"GSHB/DomFunkMod", value:DomFunk);

exit(0);


