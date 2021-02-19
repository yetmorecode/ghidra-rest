package yetmorecode.ghidrarest.util;

import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.lang.LanguageNotFoundException;
import ghidra.program.model.lang.LanguageService;
import ghidra.program.util.DefaultLanguageService;

public class LanguageUtils {
	/**
	 * Returns the language provider for the specified language name.
	 *
	 * @param languageID the language name
	 * @return the language provider for the specified language name
	 * @throws LanguageNotFoundException if no language provider exists
	 * @see ghidra.program.model.lang.Language
	 */
	public final static Language getLanguage(LanguageID languageID) throws LanguageNotFoundException {
		LanguageService service = DefaultLanguageService.getLanguageService();
		if (service != null) {
			Language language = service.getLanguage(languageID);
			if (language != null) {
				return language;
			}
		}
		throw new IllegalStateException("LanguageService does not exist.");
	}
}
