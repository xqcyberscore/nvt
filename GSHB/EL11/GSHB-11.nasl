##############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB-11.nasl 8165 2017-12-19 06:39:31Z cfischer $
#
# IT-Grundschutz, 11. Ergänzungslieferung
#
# Authors:
# Thomas Rotter <T.Rotter@dn-systems.de>
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
###############################################################################

tag_summary = "Zusammenfassung von Tests gemäß IT-Grundschutz
  (in 11. Ergänzungslieferung).

  ACHTUNG: Dieser Test wird nicht mehr unterstützt. Er wurde ersetzt durch
  den entsprechenden Test der nun permanent and die aktuelle EL angepasst
  wird: OID 1.3.6.1.4.1.25623.1.0.94171

  Diese Routinen prüfen sämtliche Maßnahmen des
  IT-Grundschutz des Bundesamts für Sicherheit
  in der Informationstechnik (BSI) auf den
  Zielsystemen soweit die Maßnahmen auf automatisierte
  Weise abgeprüft werden können.";
massnahmen = make_list("M4_001", "M4_002", "M4_003", "M4_004", "M4_005",
 "M4_006", "M4_007", "M4_008", "M4_009", "M4_010", "M4_011", "M4_012", "M4_013",
 "M4_014", "M4_015", "M4_016", "M4_017", "M4_018", "M4_019", "M4_020", "M4_021",
 "M4_022", "M4_023", "M4_024", "M4_025", "M4_026", "M4_027", "M4_028", "M4_029",
 "M4_030", "M4_031", "M4_032", "M4_033", "M4_034", "M4_035", "M4_036", "M4_037",
 "M4_038", "M4_039", "M4_040", "M4_041", "M4_042", "M4_043", "M4_044", "M4_045",
 "M4_046", "M4_047", "M4_048", "M4_049", "M4_050", "M4_051", "M4_052", "M4_053",
 "M4_054", "M4_055", "M4_056", "M4_057", "M4_058", "M4_059", "M4_060", "M4_061",
 "M4_062", "M4_063", "M4_064", "M4_065", "M4_066", "M4_067", "M4_068", "M4_069",
 "M4_070", "M4_071", "M4_072", "M4_073", "M4_074", "M4_075", "M4_076", "M4_077",
 "M4_078", "M4_079", "M4_080", "M4_081", "M4_082", "M4_083", "M4_084", "M4_085",
 "M4_086", "M4_087", "M4_088", "M4_089", "M4_090", "M4_091", "M4_092", "M4_093",
 "M4_094", "M4_095", "M4_096", "M4_097", "M4_098", "M4_099", "M4_100", "M4_101",
 "M4_102", "M4_103", "M4_104", "M4_105", "M4_106", "M4_107", "M4_108", "M4_109",
 "M4_110", "M4_111", "M4_112", "M4_113", "M4_114", "M4_115", "M4_116", "M4_117",
 "M4_118", "M4_119", "M4_120", "M4_121", "M4_122", "M4_123", "M4_124", "M4_125",
 "M4_126", "M4_127", "M4_128", "M4_129", "M4_130", "M4_131", "M4_132", "M4_133",
 "M4_134", "M4_135", "M4_136", "M4_137", "M4_138", "M4_139", "M4_140", "M4_141",
 "M4_142", "M4_143", "M4_144", "M4_145", "M4_146", "M4_147", "M4_148", "M4_149",
 "M4_150", "M4_151", "M4_152", "M4_153", "M4_154", "M4_155", "M4_156", "M4_157",
 "M4_158", "M4_159", "M4_160", "M4_161", "M4_162", "M4_163", "M4_164", "M4_165",
 "M4_166", "M4_167", "M4_168", "M4_169", "M4_170", "M4_171", "M4_172", "M4_173",
 "M4_174", "M4_175", "M4_176", "M4_177", "M4_178", "M4_179", "M4_180", "M4_181",
 "M4_182", "M4_183", "M4_184", "M4_185", "M4_186", "M4_187", "M4_188", "M4_189",
 "M4_190", "M4_191", "M4_192", "M4_193", "M4_194", "M4_195", "M4_196", "M4_197",
 "M4_198", "M4_199", "M4_200", "M4_201", "M4_202", "M4_203", "M4_204", "M4_205",
 "M4_206", "M4_207", "M4_208", "M4_209", "M4_210", "M4_211", "M4_212", "M4_213",
 "M4_214", "M4_215", "M4_216", "M4_217", "M4_218", "M4_219", "M4_220", "M4_221",
 "M4_222", "M4_223", "M4_224", "M4_225", "M4_226", "M4_227", "M4_228", "M4_229",
 "M4_230", "M4_231", "M4_232", "M4_233", "M4_234", "M4_235", "M4_236", "M4_237",
 "M4_238", "M4_239", "M4_240", "M4_241", "M4_242", "M4_243", "M4_244", "M4_245",
 "M4_246", "M4_247", "M4_248", "M4_249", "M4_250", "M4_251", "M4_252", "M4_253",
 "M4_254", "M4_255", "M4_256", "M4_257", "M4_258", "M4_259", "M4_260", "M4_261",
 "M4_262", "M4_263", "M4_264", "M4_265", "M4_266", "M4_267", "M4_268", "M4_269",
 "M4_270", "M4_271", "M4_272", "M4_273", "M4_274", "M4_275", "M4_276", "M4_277",
 "M4_278", "M4_279", "M4_280", "M4_281", "M4_282", "M4_283", "M4_284", "M4_285",
 "M4_286", "M4_287", "M4_288", "M4_289", "M4_290", "M4_291", "M4_292", "M4_293",
 "M4_294", "M4_295", "M4_296", "M4_297", "M4_298", "M4_299", "M4_300", "M4_301",
 "M4_302", "M4_303", "M4_304", "M4_305", "M4_306", "M4_307", "M4_308", "M4_309",
 "M4_310", "M4_311", "M4_312", "M4_313", "M4_314", "M4_315", "M4_316", "M4_317",
 "M4_318", "M4_319", "M4_320", "M4_321", "M4_322", "M4_323", "M4_324", "M4_325",
 "M4_326", "M4_327", "M4_328", "M4_329", "M4_330", "M4_331", "M4_332", "M4_333",
 "M4_334", "M4_335", "M4_336", "M4_337", "M4_338", "M4_339", "M4_340", "M4_341",
 "M4_342", "M4_343", "M4_344", "M4_345", "M5_001", "M5_002", "M5_003", "M5_004",
 "M5_005", "M5_006", "M5_007", "M5_008", "M5_009", "M5_010", "M5_011",
 "M5_012", "M5_013", "M5_014", "M5_015", "M5_016", "M5_017", "M5_018", "M5_019",
 "M5_020", "M5_021", "M5_022", "M5_023", "M5_024", "M5_025", "M5_026", "M5_027",
 "M5_028", "M5_029", "M5_030", "M5_031", "M5_032", "M5_033", "M5_034", "M5_035",
 "M5_036", "M5_037", "M5_038", "M5_039", "M5_040", "M5_041", "M5_042", "M5_043",
 "M5_044", "M5_045", "M5_046", "M5_047", "M5_048", "M5_049", "M5_050", "M5_051",
 "M5_052", "M5_053", "M5_054", "M5_055", "M5_056", "M5_057", "M5_058",
 "M5_059", "M5_060", "M5_061", "M5_062", "M5_063", "M5_064", "M5_065",
 "M5_066", "M5_067", "M5_068", "M5_069", "M5_070", "M5_071", "M5_072", "M5_073",
 "M5_074", "M5_075", "M5_076", "M5_077", "M5_078", "M5_079", "M5_080", "M5_081",
 "M5_082", "M5_083", "M5_084", "M5_085", "M5_086", "M5_087", "M5_088", "M5_089",
 "M5_090", "M5_091", "M5_092", "M5_093", "M5_094", "M5_095", "M5_096",
 "M5_097", "M5_098", "M5_099", "M5_100", "M5_101", "M5_102", "M5_103", "M5_104",
 "M5_105", "M5_106", "M5_107", "M5_108", "M5_109", "M5_110", "M5_111", "M5_112",
 "M5_113", "M5_114", "M5_115", "M5_116", "M5_117", "M5_118", "M5_119", "M5_120",
 "M5_121", "M5_122", "M5_123", "M5_124", "M5_125", "M5_126", "M5_127", "M5_128",
 "M5_129", "M5_130", "M5_131", "M5_132", "M5_133", "M5_134", "M5_135", "M5_136",
 "M5_137", "M5_138", "M5_139", "M5_140", "M5_141", "M5_142", "M5_143", "M5_144",
 "M5_145", "M5_146", "M5_147", "M5_148", "M5_149", "M5_150", "M5_151", "M5_152");

depend = make_list("M4_001", "M4_002", "M4_003", "M4_004", "M4_005", "M4_007",
 "M4_009", "M4_014", "M4_015", "M4_016", "M4_017", "M4_018", "M4_019", "M4_020",
 "M4_021", "M4_022", "M4_023", "M4_026", "M4_033", "M4_036", "M4_037",
 "M4_040", "M4_048", "M4_049", "M4_052", "M4_057", "M4_080", "M4_093", "M4_094",
 "M4_096", "M4_097", "M4_098", "M4_106", "M4_135", "M4_146", "M4_147", "M4_178",
 "M4_179", "M4_186", "M4_189", "M4_190", "M4_192", "M4_195", "M4_196", "M4_197",
 "M4_200", "M4_227", "M4_238", "M4_244", "M4_249", "M4_277", "M4_284", "M4_285",
 "M4_287", "M4_288", "M4_300", "M4_305", "M4_310", "M4_313", "M4_315", "M4_325",
 "M4_326", "M4_328", "M4_331", "M4_332", "M4_334", "M4_338", "M4_339", "M4_340",
 "M4_341", "M4_342", "M4_344", "M5_008", "M5_009", "M5_017", "M5_018", "M5_019",
 "M5_020", "M5_021", "M5_034", "M5_037", "M5_053", "M5_055", "M5_059", "M5_063",
 "M5_064", "M5_066", "M5_072", "M5_090", "M5_091", "M5_101", "M5_102", "M5_103",
 "M5_104", "M5_105", "M5_107", "M5_109", "M5_123", "M5_131", "M5_145", "M5_147");



if(description)
{
  script_id(895000);
  script_version("$Revision: 8165 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-19 07:39:31 +0100 (Tue, 19 Dec 2017) $");
  script_tag(name:"creation_date", value:"2010-01-14 14:29:35 +0100 (Thu, 14 Jan 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("IT-Grundschutz, 11. EL");
  # Dependency GSHB_M4_007.nasl is running in ACT_ATTACK because it depends on
  # GSHB_SSH_TELNET_BruteForce.nasl which is in ACT_ATTACK as well.
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"general_note");
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Compliance");
  script_mandatory_keys("Compliance/Launch/GSHB-11");
  script_add_preference(name:"Berichtformat", type:"radio", value:"Text;Tabellarisch;Text und Tabellarisch");
  script_require_keys("GSHB-11/silence");
  script_dependencies("compliance_tests.nasl");
  foreach d (depend) script_dependencies("GSHB/EL11/GSHB_" + d + ".nasl");
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"deprecated", value:TRUE);
  exit(0);
}

exit(66);
