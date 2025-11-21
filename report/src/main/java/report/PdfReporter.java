package report;

import active.ActiveAnalysisEngine;
import active.discovery.EndpointDiscoveryEngine;
import active.discovery.model.DiscoveryResult;
import active.model.VulnerabilityReport;
import active.validator.ContractValidationEngine;
import active.validator.model.Divergence;
import active.validator.model.ValidationResult;
import model.Severity;
import model.ValidationFinding;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.PDPageContentStream;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.apache.pdfbox.pdmodel.font.PDFont;
import org.apache.pdfbox.pdmodel.font.PDType0Font;
import org.apache.pdfbox.pdmodel.font.PDType1Font;
import org.apache.pdfbox.pdmodel.font.Standard14Fonts;
import org.apache.pdfbox.pdmodel.interactive.action.PDActionGoTo;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotationLink;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDBorderStyleDictionary;
import org.apache.pdfbox.pdmodel.interactive.documentnavigation.destination.PDPageFitDestination;

import java.awt.Color;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.time.Duration;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Генератор подробных PDF-отчетов с графиками и базой знаний об уязвимостях.
 *
 * <p>Создает профессиональный PDF-документ формата A4, предназначенный для:
 * <ul>
 *   <li>Документирования результатов анализа безопасности</li>
 *   <li>Презентации для заинтересованных сторон и менеджмента</li>
 *   <li>Архивирования результатов аудита</li>
 *   <li>Соответствия требованиям compliance</li>
 *   <li>Обучения и демонстрации проблем безопасности</li>
 * </ul>
 *
 * <p>Структура PDF-отчета:
 * <ol>
 *   <li><b>Титульная страница</b> - название спецификации, дата, режим анализа, краткая статистика</li>
 *   <li><b>Оглавление</b> - кликабельные ссылки на все разделы</li>
 *   <li><b>Статический анализ</b> - findings с группировкой по severity и круговой диаграммой</li>
 *   <li><b>Активное тестирование</b> - уязвимости с графиками и ссылками на базу знаний</li>
 *   <li><b>Валидация контракта</b> - расхождения с круговой диаграммой по severity</li>
 *   <li><b>База знаний</b> - подробная информация о каждой найденной уязвимости</li>
 * </ol>
 *
 * <p>Визуальные элементы:
 * <ul>
 *   <li>Круговые диаграммы распределения по severity</li>
 *   <li>Столбчатые диаграммы распределения по типам уязвимостей</li>
 *   <li>Цветовое кодирование по уровню критичности</li>
 *   <li>Кликабельные гиперссылки в оглавлении и на базу знаний</li>
 *   <li>Иконки для различных типов проблем</li>
 * </ul>
 *
 * <p>База знаний включает для каждой уязвимости:
 * <ul>
 *   <li>Подробное описание проблемы</li>
 *   <li>Список всех затронутых endpoint'ов</li>
 *   <li>Примеры воспроизведения уязвимости</li>
 *   <li>Рекомендации по устранению</li>
 * </ul>
 *
 * <p><b>Важно:</b> Для PDF формата следует использовать метод
 * {@link #generateToOutputStream(AnalysisReport, java.io.OutputStream)},
 * так как PDF требует бинарного вывода.
 *
 * <p>Пример использования:
 * <pre>{@code
 * PdfReporter reporter = new PdfReporter();
 * try (OutputStream out = new FileOutputStream("report.pdf")) {
 *     reporter.generateToOutputStream(analysisReport, out);
 * }
 * }</pre>
 *
 * <p>Технические детали:
 * <ul>
 *   <li>Использует Apache PDFBox для генерации PDF</li>
 *   <li>Формат: A4 (210 × 297 мм)</li>
 *   <li>Автоматическое создание новых страниц при нехватке места</li>
 *   <li>Поддержка многостраничных отчетов</li>
 *   <li>Корректная обработка длинного текста с переносами</li>
 * </ul>
 *
 * @author API Security Analyzer Team
 * @since 1.0
 * @see Reporter
 * @see AnalysisReport
 */
public final class PdfReporter implements Reporter {

    private static final float MARGIN = 50;
    private static final float PAGE_WIDTH = PDRectangle.A4.getWidth();
    private static final float PAGE_HEIGHT = PDRectangle.A4.getHeight();
    private static final DateTimeFormatter DATE_FORMATTER =
        DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss").withZone(ZoneId.systemDefault());

    private PDDocument document;
    private PDPage currentPage;
    private PDPageContentStream currentContent;
    private float yPosition;
    private List<TocEntry> tocEntries;
    private Map<String, KnowledgeBaseEntry> knowledgeBase;
    private int kbStartPage = -1;

    // Font state tracking
    private PDFont currentFont;
    private float currentFontSize;

    // Unicode fonts for Cyrillic support
    private PDFont unicodeFont;
    private PDFont unicodeBoldFont;
    private PDFont unicodeMonoFont;
    private boolean unicodeFontsLoaded = false;

    // Deferred hyperlinks - created after KB is generated
    private static class DeferredLink {
        PDPage page;
        String kbKey;
        float x;
        float y;
        float width;
        float height;

        DeferredLink(PDPage page, String kbKey, float x, float y, float width, float height) {
            this.page = page;
            this.kbKey = kbKey;
            this.x = x;
            this.y = y;
            this.width = width;
            this.height = height;
        }
    }

    private List<DeferredLink> deferredLinks;

    private static class TocEntry {
        String title;
        PDPage page;
        int level;

        TocEntry(String title, PDPage page, int level) {
            this.title = title;
            this.page = page;
            this.level = level;
        }
    }

    private static class KnowledgeBaseEntry {
        String vulnerabilityTitle;
        String vulnerabilityType;
        String description;
        List<String> affectedEndpoints;
        String reproductionExample;
        List<String> recommendations;
        PDPage page;

        KnowledgeBaseEntry(VulnerabilityReport vuln) {
            this.vulnerabilityTitle = vuln.getTitle();
            this.vulnerabilityType = vuln.getType().getDisplayName();
            this.description = vuln.getDescription();
            this.affectedEndpoints = new ArrayList<>();
            this.reproductionExample = vuln.getReproductionSteps();
            this.recommendations = vuln.getRecommendations();
        }
    }

    /**
     * {@inheritDoc}
     *
     * <p><b>Примечание:</b> Этот метод не подходит для генерации PDF, так как PDF
     * требует бинарного вывода. Используйте {@link #generateToOutputStream(AnalysisReport, java.io.OutputStream)}
     * вместо этого метода.
     *
     * @throws IOException если запись не удалась
     */
    @Override
    public void generate(AnalysisReport report, PrintWriter writer) throws IOException {
        writer.println("PDF format requires binary output. Use generateToOutputStream() method instead.");
    }

    /**
     * Генерирует PDF-отчет и записывает его в указанный поток вывода.
     *
     * <p>Это основной метод для создания PDF-отчетов. Создает полноценный
     * многостраничный PDF-документ со всеми разделами, графиками и базой знаний.
     *
     * <p>Процесс генерации включает:
     * <ol>
     *   <li>Создание титульной страницы</li>
     *   <li>Создание оглавления (заполняется в конце)</li>
     *   <li>Сбор информации для базы знаний</li>
     *   <li>Генерация основных разделов с результатами</li>
     *   <li>Генерация базы знаний</li>
     *   <li>Создание гиперссылок</li>
     *   <li>Заполнение оглавления</li>
     *   <li>Сохранение в поток</li>
     * </ol>
     *
     * @param report объект отчета о результатах анализа
     * @param outputStream поток вывода для записи PDF (будет автоматически закрыт)
     * @throws IOException если возникла ошибка при генерации или записи PDF
     * @throws NullPointerException если {@code report} или {@code outputStream} равны null
     */
    public void generateToOutputStream(AnalysisReport report, java.io.OutputStream outputStream)
            throws IOException {
        document = new PDDocument();
        tocEntries = new ArrayList<>();
        knowledgeBase = new LinkedHashMap<>();
        deferredLinks = new ArrayList<>();
        currentContent = null;
        unicodeFontsLoaded = false;
        unicodeFont = null;
        unicodeBoldFont = null;
        unicodeMonoFont = null;

        try {
            // Load Unicode fonts for Cyrillic support
            loadUnicodeFonts();

            // 1. Title page
            generateTitlePage(report);
            closeCurrentContent();

            // 2. Table of contents (will be filled later)
            PDPage tocPage = addNewPage();
            // Don't add TOC itself to TOC entries - it's self-referential and useless

            // 3. Collect all vulnerabilities for Knowledge Base
            if (report.hasActiveResults()) {
                collectVulnerabilitiesForKB(report.getActiveResult());
            }

            // 4. Main content sections (KB links will be added later)
            if (report.hasStaticResults()) {
                generateStaticSection(report.getStaticResult());
                closeCurrentContent();
            }

            if (report.hasActiveResults()) {
                generateActiveSection(report.getActiveResult());
                closeCurrentContent();
            }

            if (report.hasContractResults()) {
                generateContractSection(report.getContractResult());
                closeCurrentContent();
            }

            if (report.hasDiscoveryResults()) {
                generateDiscoverySection(report.getDiscoveryResult());
                closeCurrentContent();
            }

            // 5. Generate Knowledge Base at the END
            if (!knowledgeBase.isEmpty()) {
                generateKnowledgeBase();
                closeCurrentContent();
            }

            // 6. Now apply all deferred hyperlinks
            applyDeferredLinks();

            // 7. Fill in the TOC with hyperlinks
            fillTableOfContents(tocPage);
            closeCurrentContent();

            // Save to output stream
            document.save(outputStream);

        } finally {
            closeCurrentContent();
            document.close();
        }
    }

    private void closeCurrentContent() throws IOException {
        if (currentContent != null) {
            currentContent.close();
            currentContent = null;
        }
    }

    private PDPage addNewPage() throws IOException {
        // Save current font state
        PDFont savedFont = currentFont;
        float savedFontSize = currentFontSize;

        closeCurrentContent();
        currentPage = new PDPage(PDRectangle.A4);
        document.addPage(currentPage);
        currentContent = new PDPageContentStream(document, currentPage);
        yPosition = PAGE_HEIGHT - 100;

        // Restore font if we had one
        if (savedFont != null && savedFontSize > 0) {
            setFont(savedFont, savedFontSize);
        }

        return currentPage;
    }

    private void checkPageSpace(float neededSpace) throws IOException {
        if (yPosition < MARGIN + neededSpace) {
            addNewPage();
        }
    }

    private void setFont(PDFont font, float size) throws IOException {
        currentFont = font;
        currentFontSize = size;
        currentContent.setFont(font, size);
    }

    /**
     * Load Unicode fonts that support Cyrillic characters.
     * Falls back to standard fonts if Unicode fonts are not available.
     */
    private void loadUnicodeFonts() throws IOException {
        if (unicodeFontsLoaded) {
            return;
        }

        try {
            // Try to load DejaVu Sans from resources
            try (InputStream fontStream = getClass().getResourceAsStream("/fonts/DejaVuSans.ttf")) {
                if (fontStream != null) {
                    unicodeFont = PDType0Font.load(document, fontStream, true);
                }
            }

            try (InputStream boldStream = getClass().getResourceAsStream("/fonts/DejaVuSans-Bold.ttf")) {
                if (boldStream != null) {
                    unicodeBoldFont = PDType0Font.load(document, boldStream, true);
                }
            }

            // For mono font, we'll use the regular font as fallback
            unicodeMonoFont = unicodeFont;

            unicodeFontsLoaded = true;
        } catch (Exception e) {
            // If loading fails, we'll use fallback fonts
            unicodeFontsLoaded = true;
        }
    }

    /**
     * Get the appropriate font for regular text.
     * Uses Unicode font if available, otherwise falls back to Helvetica.
     */
    private PDFont getRegularFont() {
        if (unicodeFont != null) {
            return unicodeFont;
        }
        return new PDType1Font(Standard14Fonts.FontName.HELVETICA);
    }

    /**
     * Get the appropriate font for bold text.
     * Uses Unicode bold font if available, otherwise falls back to Helvetica-Bold.
     */
    private PDFont getBoldFont() {
        if (unicodeBoldFont != null) {
            return unicodeBoldFont;
        }
        return new PDType1Font(Standard14Fonts.FontName.HELVETICA_BOLD);
    }

    /**
     * Get the appropriate font for monospace text.
     * Uses Unicode font if available, otherwise falls back to Courier.
     */
    private PDFont getMonoFont() {
        if (unicodeMonoFont != null) {
            return unicodeMonoFont;
        }
        return new PDType1Font(Standard14Fonts.FontName.COURIER);
    }

    private void generateTitlePage(AnalysisReport report) throws IOException {
        addNewPage();

        setFont(getBoldFont(), 28);
        drawText("API Security Analysis Report", MARGIN, yPosition);
        yPosition -= 60;

        setFont(getRegularFont(), 14);
        // Use spec title if available, otherwise extract name from location
        String specName = (report.getSpecTitle() != null && !report.getSpecTitle().isEmpty())
            ? report.getSpecTitle()
            : extractSpecName(report.getSpecLocation());
        drawText("Specification: " + specName, MARGIN, yPosition);
        yPosition -= 25;

        String dateStr = DATE_FORMATTER.format(report.getEndTime());
        drawText("Report Date: " + dateStr, MARGIN, yPosition);
        yPosition -= 25;

        drawText("Analysis Type: " + report.getMode(), MARGIN, yPosition);
        yPosition -= 40;

        setFont(getBoldFont(), 16);
        drawText("Included Analysis Types:", MARGIN, yPosition);
        yPosition -= 25;

        setFont(getRegularFont(), 12);
        if (report.hasStaticResults()) {
            drawText("  * Static Analysis", MARGIN + 10, yPosition);
            yPosition -= 20;
        }
        if (report.hasActiveResults()) {
            drawText("  * Active Security Testing", MARGIN + 10, yPosition);
            yPosition -= 20;
        }
        if (report.hasContractResults()) {
            drawText("  * Contract Validation", MARGIN + 10, yPosition);
            yPosition -= 20;
        }

        yPosition -= 30;

        setFont(getBoldFont(), 16);
        drawText("Summary Statistics:", MARGIN, yPosition);
        yPosition -= 25;

        setFont(getRegularFont(), 12);
        drawText("Total Issues Found: " + report.getTotalIssueCount(), MARGIN + 10, yPosition);
        yPosition -= 20;

        Duration duration = Duration.between(report.getStartTime(), report.getEndTime());
        drawText("Analysis Duration: " + formatDuration(duration), MARGIN + 10, yPosition);
    }

    private void fillTableOfContents(PDPage tocPage) throws IOException {
        closeCurrentContent();
        // Use APPEND mode to not overwrite the page if it has any content
        currentContent = new PDPageContentStream(document, tocPage,
            PDPageContentStream.AppendMode.OVERWRITE, true);
        yPosition = PAGE_HEIGHT - 100;
        currentPage = tocPage;

        setFont(getBoldFont(), 20);
        drawText("Table of Contents", MARGIN, yPosition);
        yPosition -= 40;

        setFont(getRegularFont(), 12);
        int pageNum = 1;
        for (TocEntry entry : tocEntries) {
            checkPageSpace(25);
            float indent = MARGIN + (entry.level * 15);

            String title = entry.title;
            String dots = " " + ".".repeat(Math.max(0, 50 - title.length()));
            String pageText = " Page " + pageNum;

            // Create clickable link
            float linkY = yPosition;
            PDAnnotationLink link = new PDAnnotationLink();
            PDRectangle linkRect = new PDRectangle(indent, linkY - 2, 400, 15);
            link.setRectangle(linkRect);

            PDBorderStyleDictionary borderStyle = new PDBorderStyleDictionary();
            borderStyle.setWidth(0);
            link.setBorderStyle(borderStyle);
            link.setColor(new org.apache.pdfbox.pdmodel.graphics.color.PDColor(
                new float[]{0, 0, 1}, org.apache.pdfbox.pdmodel.graphics.color.PDDeviceRGB.INSTANCE));

            PDPageFitDestination dest = new PDPageFitDestination();
            dest.setPage(entry.page);

            PDActionGoTo action = new PDActionGoTo();
            action.setDestination(dest);
            link.setAction(action);

            currentPage.getAnnotations().add(link);

            // Draw text in blue to show it's a link
            try {
                currentContent.setNonStrokingColor(0, 0, 0.8f);
                drawText(title + dots + pageText, indent, yPosition);
                currentContent.setNonStrokingColor(Color.BLACK);
            } catch (IOException e) {
                currentContent.setNonStrokingColor(Color.BLACK);
                throw e;
            }

            yPosition -= 20;
            pageNum++;
        }
    }

    private void collectVulnerabilitiesForKB(AnalysisReport.ActiveAnalysisResult result) {
        if (result.hasError()) {
            return;
        }

        ActiveAnalysisEngine.AnalysisReport activeReport = result.getReport();

        // Collect vulnerabilities for knowledge base
        for (ActiveAnalysisEngine.EndpointAnalysisResult endpointResult : activeReport.getEndpointResults()) {
            String endpoint = endpointResult.endpoint().toString();
            for (VulnerabilityReport vuln : endpointResult.getAllVulnerabilities()) {
                String kbKey = vuln.getTitle() != null ? vuln.getTitle() : vuln.getType().name();
                knowledgeBase.computeIfAbsent(kbKey, k -> new KnowledgeBaseEntry(vuln));
                knowledgeBase.get(kbKey).affectedEndpoints.add(endpoint);
            }
        }
    }

    private void generateStaticSection(AnalysisReport.StaticAnalysisResult result) throws IOException {
        PDPage sectionPage = addNewPage();
        tocEntries.add(new TocEntry("Static Analysis", sectionPage, 0));

        setFont(getBoldFont(), 22);
        drawText("Static Analysis", MARGIN, yPosition);
        yPosition -= 40;

        if (result.hasError()) {
            setFont(getRegularFont(), 12);
            currentContent.setNonStrokingColor(Color.RED);
            drawText("Error: " + result.getErrorMessage(), MARGIN, yPosition);
            currentContent.setNonStrokingColor(Color.BLACK);
            return;
        }

        List<ValidationFinding> findings = result.getFindings();

        // Summary
        setFont(getBoldFont(), 16);
        drawText("Summary", MARGIN, yPosition);
        yPosition -= 25;

        setFont(getRegularFont(), 12);
        drawText("Total Findings: " + findings.size(), MARGIN + 10, yPosition);
        yPosition -= 40;

        // Severity distribution with pie chart
        Map<Severity, Long> severityCounts = findings.stream()
            .collect(Collectors.groupingBy(ValidationFinding::getSeverity, Collectors.counting()));

        if (!severityCounts.isEmpty()) {
            setFont(getBoldFont(), 14);
            drawText("Severity Distribution:", MARGIN + 10, yPosition);
            yPosition -= 30;

            drawPieChart(severityCounts);
            yPosition -= 30;
        }

        // Findings by endpoint
        Map<String, List<ValidationFinding>> byEndpoint = groupStaticByEndpoint(findings);
        for (Map.Entry<String, List<ValidationFinding>> entry : byEndpoint.entrySet()) {
            checkPageSpace(60);

            setFont(getBoldFont(), 13);
            drawText("Endpoint: " + entry.getKey(), MARGIN, yPosition);
            yPosition -= 20;

            for (ValidationFinding finding : entry.getValue()) {
                checkPageSpace(40);
                drawFinding(finding);
                yPosition -= 10;
            }
            yPosition -= 10;
        }
    }

    private void generateActiveSection(AnalysisReport.ActiveAnalysisResult result) throws IOException {
        PDPage sectionPage = addNewPage();
        tocEntries.add(new TocEntry("Active Security Testing", sectionPage, 0));

        setFont(getBoldFont(), 22);
        drawText("Active Security Testing", MARGIN, yPosition);
        yPosition -= 40;

        if (result.hasError()) {
            setFont(getRegularFont(), 12);
            currentContent.setNonStrokingColor(Color.RED);
            drawText("Error: " + result.getErrorMessage(), MARGIN, yPosition);
            currentContent.setNonStrokingColor(Color.BLACK);
            return;
        }

        ActiveAnalysisEngine.AnalysisReport activeReport = result.getReport();

        // Summary
        setFont(getBoldFont(), 16);
        drawText("Summary", MARGIN, yPosition);
        yPosition -= 25;

        setFont(getRegularFont(), 12);
        drawText("Endpoints Scanned: " + activeReport.getEndpointCount(), MARGIN + 10, yPosition);
        yPosition -= 18;
        drawText("Vulnerable Endpoints: " + activeReport.getVulnerableEndpointCount(), MARGIN + 10, yPosition);
        yPosition -= 18;
        drawText("Total Vulnerabilities: " + activeReport.getTotalVulnerabilityCount(), MARGIN + 10, yPosition);
        yPosition -= 40;

        // Severity distribution with pie chart
        Map<Severity, Long> severityCounts = activeReport.getVulnerabilityCountBySeverity();
        if (!severityCounts.isEmpty()) {
            setFont(getBoldFont(), 14);
            drawText("Severity Distribution:", MARGIN + 10, yPosition);
            yPosition -= 30;

            drawPieChart(severityCounts);
            yPosition -= 30;
        }

        // Vulnerability types distribution with bar chart
        Map<String, Long> typeCounts = new LinkedHashMap<>();
        for (ActiveAnalysisEngine.EndpointAnalysisResult endpointResult : activeReport.getEndpointResults()) {
            for (VulnerabilityReport vuln : endpointResult.getAllVulnerabilities()) {
                String type = vuln.getType().getDisplayName();
                typeCounts.put(type, typeCounts.getOrDefault(type, 0L) + 1);
            }
        }

        if (!typeCounts.isEmpty()) {
            checkPageSpace(200);
            setFont(getBoldFont(), 14);
            drawText("Vulnerability Types Distribution:", MARGIN + 10, yPosition);
            yPosition -= 30;

            // Sort by count descending
            Map<String, Long> sortedTypeCounts = typeCounts.entrySet().stream()
                .sorted(Map.Entry.<String, Long>comparingByValue().reversed())
                .collect(Collectors.toMap(
                    Map.Entry::getKey,
                    Map.Entry::getValue,
                    (e1, e2) -> e1,
                    LinkedHashMap::new
                ));

            drawBarChart(sortedTypeCounts);
            yPosition -= 30;
        }

        // Vulnerabilities by endpoint with KB links (KB already generated at this point)
        for (ActiveAnalysisEngine.EndpointAnalysisResult endpointResult : activeReport.getEndpointResults()) {
            if (endpointResult.getAllVulnerabilities().isEmpty()) continue;

            checkPageSpace(60);

            setFont(getBoldFont(), 13);
            drawText("Endpoint: " + endpointResult.endpoint().toString(), MARGIN, yPosition);
            yPosition -= 20;

            for (VulnerabilityReport vuln : endpointResult.getAllVulnerabilities()) {
                checkPageSpace(50);
                drawVulnerabilityWithKBLink(vuln);
                yPosition -= 10;
            }
            yPosition -= 10;
        }
    }

    private void generateContractSection(AnalysisReport.ContractAnalysisResult result) throws IOException {
        PDPage sectionPage = addNewPage();
        tocEntries.add(new TocEntry("Contract Validation", sectionPage, 0));

        setFont(getBoldFont(), 22);
        drawText("Contract Validation", MARGIN, yPosition);
        yPosition -= 40;

        if (result.hasError()) {
            setFont(getRegularFont(), 12);
            currentContent.setNonStrokingColor(Color.RED);
            drawText("Error: " + result.getErrorMessage(), MARGIN, yPosition);
            currentContent.setNonStrokingColor(Color.BLACK);
            return;
        }

        ContractValidationEngine.ContractValidationReport contractReport = result.getReport();

        // Summary
        setFont(getBoldFont(), 16);
        drawText("Summary", MARGIN, yPosition);
        yPosition -= 25;

        setFont(getRegularFont(), 12);
        drawText("Total Endpoints: " + contractReport.getTotalEndpoints(), MARGIN + 10, yPosition);
        yPosition -= 18;
        drawText("Total Divergences: " + contractReport.getTotalDivergences(), MARGIN + 10, yPosition);
        yPosition -= 18;
        drawText("Critical Divergences: " + contractReport.getCriticalDivergences(), MARGIN + 10, yPosition);
        yPosition -= 40;

        // Severity distribution with pie chart
        Map<Object, Long> divSeverityCounts = new LinkedHashMap<>();
        for (var entry : contractReport.getDivergencesBySeverity().entrySet()) {
            divSeverityCounts.put(entry.getKey(), (long) entry.getValue().size());
        }

        if (!divSeverityCounts.isEmpty()) {
            setFont(getBoldFont(), 14);
            drawText("Severity Distribution:", MARGIN + 10, yPosition);
            yPosition -= 30;

            drawPieChartGeneric(divSeverityCounts);
            yPosition -= 30;
        }

        // Divergences by endpoint
        Map<String, List<Divergence>> byEndpoint = groupContractByEndpoint(contractReport.getResults());
        for (Map.Entry<String, List<Divergence>> entry : byEndpoint.entrySet()) {
            checkPageSpace(60);

            setFont(getBoldFont(), 13);
            drawText("Endpoint: " + entry.getKey(), MARGIN, yPosition);
            yPosition -= 20;

            for (Divergence div : entry.getValue()) {
                checkPageSpace(40);
                drawDivergence(div);
                yPosition -= 10;
            }
            yPosition -= 10;
        }
    }

    private void generateDiscoverySection(AnalysisReport.DiscoveryAnalysisResult result) throws IOException {
        PDPage sectionPage = addNewPage();
        tocEntries.add(new TocEntry("Endpoint Discovery", sectionPage, 0));

        setFont(getBoldFont(), 22);
        drawText("Endpoint Discovery", MARGIN, yPosition);
        yPosition -= 40;

        if (result.hasError()) {
            setFont(getRegularFont(), 12);
            currentContent.setNonStrokingColor(Color.RED);
            drawText("Error: " + result.getErrorMessage(), MARGIN, yPosition);
            currentContent.setNonStrokingColor(Color.BLACK);
            return;
        }

        EndpointDiscoveryEngine.DiscoveryReport discoveryReport = result.getReport();

        // Summary
        setFont(getBoldFont(), 16);
        drawText("Summary", MARGIN, yPosition);
        yPosition -= 25;

        setFont(getRegularFont(), 12);
        drawText("Strategy: " + discoveryReport.getConfig().getStrategy().name(), MARGIN + 10, yPosition);
        yPosition -= 18;
        drawText("Total Undocumented Endpoints: " + discoveryReport.getTotalCount(), MARGIN + 10, yPosition);
        yPosition -= 18;
        drawText("Critical Findings: " + discoveryReport.getCriticalResults().size(), MARGIN + 10, yPosition);
        yPosition -= 18;
        drawText("High Findings: " + discoveryReport.getHighResults().size(), MARGIN + 10, yPosition);
        yPosition -= 18;
        drawText("Duration: " + formatDuration(discoveryReport.getDuration()), MARGIN + 10, yPosition);
        yPosition -= 40;

        // Severity distribution with pie chart
        Map<Severity, Long> severityCounts = discoveryReport.getCountBySeverity();
        if (!severityCounts.isEmpty()) {
            setFont(getBoldFont(), 14);
            drawText("Severity Distribution:", MARGIN + 10, yPosition);
            yPosition -= 30;

            drawPieChart(severityCounts);
            yPosition -= 30;
        }

        // Discovery method distribution
        Map<String, Long> methodCounts = new LinkedHashMap<>();
        for (var entry : discoveryReport.getCountByMethod().entrySet()) {
            methodCounts.put(entry.getKey().name(), entry.getValue());
        }

        if (!methodCounts.isEmpty()) {
            checkPageSpace(200);
            setFont(getBoldFont(), 14);
            drawText("Discovery Method Distribution:", MARGIN + 10, yPosition);
            yPosition -= 30;

            drawBarChart(methodCounts);
            yPosition -= 30;
        }

        // Detailed results by severity
        Map<Severity, List<DiscoveryResult>> groupedBySeverity = discoveryReport.getResults().stream()
            .collect(Collectors.groupingBy(DiscoveryResult::getSeverity));

        for (Severity severity : Severity.values()) {
            List<DiscoveryResult> severityResults = groupedBySeverity.get(severity);
            if (severityResults == null || severityResults.isEmpty()) {
                continue;
            }

            checkPageSpace(60);

            setFont(getBoldFont(), 14);
            drawText(severity.getDisplayName() + " Severity Findings (" + severityResults.size() + ")",
                MARGIN, yPosition);
            yPosition -= 20;

            for (DiscoveryResult discoveryResult : severityResults) {
                checkPageSpace(50);
                drawDiscoveryResult(discoveryResult);
                yPosition -= 10;
            }
            yPosition -= 10;
        }
    }

    private void drawDiscoveryResult(DiscoveryResult discoveryResult) throws IOException {
        setFont(getBoldFont(), 11);
        Color severityColor = getSeverityColor(discoveryResult.getSeverity().toString());
        currentContent.setNonStrokingColor(severityColor);
        drawText("[" + discoveryResult.getSeverity() + "] " +
            discoveryResult.getEndpoint().getMethod() + " " +
            discoveryResult.getEndpoint().getPath(), MARGIN + 20, yPosition);
        currentContent.setNonStrokingColor(Color.BLACK);
        yPosition -= 15;

        setFont(getRegularFont(), 10);
        drawText("Status Code: " + discoveryResult.getStatusCode(), MARGIN + 30, yPosition);
        yPosition -= 12;
        drawText("Discovery Method: " + discoveryResult.getDiscoveryMethod().name(), MARGIN + 30, yPosition);
        yPosition -= 12;
        drawText("Response Time: " + discoveryResult.getResponseTimeMs() + "ms", MARGIN + 30, yPosition);
        yPosition -= 12;

        if (discoveryResult.getReason() != null && !discoveryResult.getReason().isEmpty()) {
            String reason = discoveryResult.getReason();
            if (reason.length() > 100) {
                reason = reason.substring(0, 97) + "...";
            }
            drawText("Reason: " + reason, MARGIN + 30, yPosition);
            yPosition -= 12;
        }

        yPosition -= 3;
    }

    private void generateKnowledgeBase() throws IOException {
        PDPage kbPage = addNewPage();
        kbStartPage = document.getPages().indexOf(kbPage);
        tocEntries.add(new TocEntry("Knowledge Base", kbPage, 0));

        setFont(getBoldFont(), 22);
        drawText("Knowledge Base", MARGIN, yPosition);
        yPosition -= 40;

        setFont(getRegularFont(), 11);
        drawText("Detailed information about detected vulnerabilities", MARGIN, yPosition);
        yPosition -= 40;

        for (Map.Entry<String, KnowledgeBaseEntry> entry : knowledgeBase.entrySet()) {
            KnowledgeBaseEntry kbEntry = entry.getValue();

            // Record page for this KB entry
            checkPageSpace(200);
            kbEntry.page = currentPage;

            setFont(getBoldFont(), 16);
            drawText(kbEntry.vulnerabilityTitle != null ? kbEntry.vulnerabilityTitle : kbEntry.vulnerabilityType,
                MARGIN, yPosition);
            yPosition -= 20;

            setFont(getRegularFont(), 11);
            currentContent.setNonStrokingColor(new Color(100, 100, 100));
            drawText("Type: " + kbEntry.vulnerabilityType, MARGIN, yPosition);
            currentContent.setNonStrokingColor(Color.BLACK);
            yPosition -= 25;

            setFont(getBoldFont(), 12);
            drawText("Description:", MARGIN + 10, yPosition);
            yPosition -= 15;

            setFont(getRegularFont(), 10);
            yPosition = drawWrappedText(kbEntry.description, MARGIN + 20, yPosition, PAGE_WIDTH - 2 * MARGIN - 20);
            yPosition -= 15;

            setFont(getBoldFont(), 12);
            drawText("Affected Endpoints (" + kbEntry.affectedEndpoints.size() + "):", MARGIN + 10, yPosition);
            yPosition -= 15;

            setFont(getRegularFont(), 9);
            for (String endpoint : kbEntry.affectedEndpoints.stream().limit(10).collect(Collectors.toList())) {
                checkPageSpace(15);
                drawText("  - " + endpoint, MARGIN + 20, yPosition);
                yPosition -= 12;
            }
            if (kbEntry.affectedEndpoints.size() > 10) {
                drawText("  ... and " + (kbEntry.affectedEndpoints.size() - 10) + " more", MARGIN + 20, yPosition);
                yPosition -= 12;
            }
            yPosition -= 10;

            if (kbEntry.reproductionExample != null && !kbEntry.reproductionExample.isEmpty()) {
                checkPageSpace(60);
                setFont(getBoldFont(), 12);
                drawText("Reproduction Example:", MARGIN + 10, yPosition);
                yPosition -= 15;

                setFont(getMonoFont(), 9);
                yPosition = drawTextWithLineBreaks(kbEntry.reproductionExample, MARGIN + 20, yPosition,
                    PAGE_WIDTH - 2 * MARGIN - 20);
                yPosition -= 15;
            }

            if (kbEntry.recommendations != null && !kbEntry.recommendations.isEmpty()) {
                checkPageSpace(40);
                setFont(getBoldFont(), 12);
                drawText("Recommendations:", MARGIN + 10, yPosition);
                yPosition -= 15;

                setFont(getRegularFont(), 10);
                for (String rec : kbEntry.recommendations) {
                    checkPageSpace(30);
                    yPosition = drawWrappedText("  • " + rec, MARGIN + 20, yPosition,
                        PAGE_WIDTH - 2 * MARGIN - 20);
                    yPosition -= 10;
                }
            }

            yPosition -= 30;
        }
    }

    // Drawing methods
    private void drawPieChart(Map<Severity, Long> data) throws IOException {
        drawPieChartGeneric(new LinkedHashMap<>(data));
    }

    private void drawPieChartGeneric(Map<Object, Long> data) throws IOException {
        float centerX = PAGE_WIDTH / 2;
        float centerY = yPosition - 150;
        float radius = 120;

        long total = data.values().stream().mapToLong(Long::longValue).sum();
        if (total == 0) return;

        float startAngle = 0;

        for (Map.Entry<Object, Long> entry : data.entrySet()) {
            float sweepAngle = (entry.getValue() * 360.0f) / total;

            Color color = getColorForSeverity(entry.getKey().toString());
            currentContent.setNonStrokingColor(color);

            drawPieSlice(centerX, centerY, radius, startAngle, sweepAngle);

            startAngle += sweepAngle;
        }

        // Draw legend
        float legendY = centerY - radius - 30;
        float legendX = centerX - 150;

        setFont(getRegularFont(), 10);
        for (Map.Entry<Object, Long> entry : data.entrySet()) {
            checkPageSpace(15);

            Color color = getColorForSeverity(entry.getKey().toString());
            currentContent.setNonStrokingColor(color);
            currentContent.addRect(legendX, legendY - 8, 10, 10);
            currentContent.fill();

            currentContent.setNonStrokingColor(Color.BLACK);
            double percentage = (entry.getValue() * 100.0) / total;
            String label = String.format("%s: %d (%.1f%%)", entry.getKey(), entry.getValue(), percentage);
            drawText(label, legendX + 15, legendY - 8);

            legendY -= 15;
        }

        yPosition = legendY - 10;
    }

    private void drawPieSlice(float centerX, float centerY, float radius, float startAngle, float sweepAngle)
            throws IOException {
        if (sweepAngle == 0) return;

        currentContent.moveTo(centerX, centerY);

        // Draw arc by approximating with line segments
        int segments = Math.max(8, (int)(sweepAngle / 10));
        for (int i = 0; i <= segments; i++) {
            float angle = (float) Math.toRadians(startAngle + (sweepAngle * i / segments));
            float x = centerX + radius * (float) Math.cos(angle);
            float y = centerY + radius * (float) Math.sin(angle);
            currentContent.lineTo(x, y);
        }

        currentContent.closePath();
        currentContent.fill();
    }

    private void drawBarChart(Map<String, Long> data) throws IOException {
        long maxValue = data.values().stream().mapToLong(Long::longValue).max().orElse(1);
        float barHeight = 25;
        float maxBarWidth = PAGE_WIDTH - 2 * MARGIN - 180;
        float startX = MARGIN + 20;
        float currentY = yPosition;

        setFont(getRegularFont(), 11);

        // Define vibrant colors for bars
        Color[] colors = new Color[]{
            new Color(59, 130, 246),    // Blue
            new Color(220, 38, 38),     // Red
            new Color(234, 179, 8),     // Yellow
            new Color(34, 197, 94),     // Green
            new Color(168, 85, 247),    // Purple
            new Color(236, 72, 153),    // Pink
            new Color(249, 115, 22),    // Orange
            new Color(20, 184, 166),    // Teal
            new Color(139, 92, 246),    // Violet
            new Color(14, 165, 233)     // Sky
        };

        int colorIndex = 0;

        for (Map.Entry<String, Long> entry : data.entrySet()) {
            checkPageSpace(barHeight + 10);

            String label = entry.getKey();
            long count = entry.getValue();
            float barWidth = (count * maxBarWidth) / maxValue;

            // Draw label
            currentContent.setNonStrokingColor(Color.BLACK);
            drawText(label + ": " + count, startX, currentY - 8);

            // Draw colored bar
            Color barColor = colors[colorIndex % colors.length];
            currentContent.setNonStrokingColor(barColor);
            currentContent.addRect(startX + 200, currentY - barHeight + 5, barWidth, barHeight - 5);
            currentContent.fill();

            currentY -= barHeight + 5;
            colorIndex++;
        }

        yPosition = currentY;
        currentContent.setNonStrokingColor(Color.BLACK);
    }

    private void drawFinding(ValidationFinding finding) throws IOException {
        setFont(getBoldFont(), 11);
        Color severityColor = getSeverityColor(finding.getSeverity().toString());
        currentContent.setNonStrokingColor(severityColor);
        drawText("[" + finding.getSeverity() + "] " + finding.getType(), MARGIN + 20, yPosition);
        currentContent.setNonStrokingColor(Color.BLACK);
        yPosition -= 15;

        setFont(getRegularFont(), 10);
        String details = finding.getDetails();
        if (details != null && details.length() > 100) {
            details = details.substring(0, 97) + "...";
        }
        drawText(details, MARGIN + 30, yPosition);
        yPosition -= 15;
    }

    private void drawVulnerabilityWithKBLink(VulnerabilityReport vuln) throws IOException {
        try {
            // KB will be generated later, so just store deferred link info
            String kbKey = vuln.getTitle() != null ? vuln.getTitle() : vuln.getType().name();

            setFont(getBoldFont(), 11);

            String title = "[" + vuln.getSeverity() + "] " + (vuln.getTitle() != null ? vuln.getTitle() : "Unknown");
            float titleY = yPosition;

            // Draw title in blue to indicate it will be a clickable link
            currentContent.setNonStrokingColor(0, 0, 0.8f);
            drawText(title, MARGIN + 20, yPosition);
            currentContent.setNonStrokingColor(Color.BLACK);

            // Store deferred link for later creation (after KB is generated)
            float textWidth = title.length() * 6.5f;
            deferredLinks.add(new DeferredLink(currentPage, kbKey, MARGIN + 20, titleY - 2, textWidth, 13));

            yPosition -= 15;

            // Draw description
            setFont(getRegularFont(), 10);
            String description = vuln.getDescription();
            if (description != null) {
                if (description.length() > 100) {
                    description = description.substring(0, 97) + "...";
                }
                drawText(description, MARGIN + 30, yPosition);
            }
            yPosition -= 15;

        } catch (Exception e) {
            // Reset color to black in case of any error
            currentContent.setNonStrokingColor(Color.BLACK);
            throw new IOException("Error drawing vulnerability: " + e.getMessage(), e);
        }
    }

    private void drawDivergence(Divergence div) throws IOException {
        setFont(getBoldFont(), 11);
        Color severityColor = getSeverityColor(div.getSeverity().name());
        currentContent.setNonStrokingColor(severityColor);
        drawText("[" + div.getSeverity() + "] " + div.getType(), MARGIN + 20, yPosition);
        currentContent.setNonStrokingColor(Color.BLACK);
        yPosition -= 15;

        setFont(getRegularFont(), 10);
        String message = div.getMessage();
        if (message != null && message.length() > 100) {
            message = message.substring(0, 97) + "...";
        }
        drawText(message, MARGIN + 30, yPosition);
        yPosition -= 15;
    }

    /**
     * Apply all deferred hyperlinks after Knowledge Base has been generated.
     * This allows us to create links to KB entries even though KB is at the end.
     */
    private void applyDeferredLinks() throws IOException {
        for (DeferredLink link : deferredLinks) {
            KnowledgeBaseEntry kbEntry = knowledgeBase.get(link.kbKey);

            // Only create link if KB entry exists and has a page assigned
            if (kbEntry != null && kbEntry.page != null) {
                PDAnnotationLink annotation = new PDAnnotationLink();
                PDRectangle linkRect = new PDRectangle(link.x, link.y, link.width, link.height);
                annotation.setRectangle(linkRect);

                // No visible border
                PDBorderStyleDictionary borderStyle = new PDBorderStyleDictionary();
                borderStyle.setWidth(0);
                annotation.setBorderStyle(borderStyle);

                // Create destination to KB page
                PDPageFitDestination dest = new PDPageFitDestination();
                dest.setPage(kbEntry.page);

                // Create goto action
                PDActionGoTo action = new PDActionGoTo();
                action.setDestination(dest);
                annotation.setAction(action);

                // Add annotation to the page where the link was drawn
                link.page.getAnnotations().add(annotation);
            }
        }
    }

    // Helper methods
    private Map<String, List<ValidationFinding>> groupStaticByEndpoint(List<ValidationFinding> findings) {
        Map<String, List<ValidationFinding>> grouped = new LinkedHashMap<>();
        for (ValidationFinding finding : findings) {
            String key = (finding.getMethod() != null ? finding.getMethod() + " " : "") +
                (finding.getPath() != null ? finding.getPath() : "General");
            grouped.computeIfAbsent(key, k -> new ArrayList<>()).add(finding);
        }
        return grouped;
    }

    private Map<String, List<Divergence>> groupContractByEndpoint(List<ValidationResult> results) {
        Map<String, List<Divergence>> grouped = new LinkedHashMap<>();
        for (ValidationResult result : results) {
            for (Divergence div : result.getDivergences()) {
                String key = div.getPath();
                grouped.computeIfAbsent(key, k -> new ArrayList<>()).add(div);
            }
        }
        return grouped;
    }

    // Utility methods
    private void drawText(String text, float x, float y) throws IOException {
        if (text == null) text = "";

        // Sanitize text - remove characters that might cause issues
        text = text.replace('\r', ' ').replace('\n', ' ').replace('\t', ' ');

        currentContent.beginText();
        try {
            currentContent.newLineAtOffset(x, y);
            currentContent.showText(text);
        } finally {
            currentContent.endText();
        }
    }

    private float drawWrappedText(String text, float x, float y, float maxWidth) throws IOException {
        if (text == null || text.isEmpty()) return y;

        String[] words = text.split(" ");
        StringBuilder line = new StringBuilder();

        for (String word : words) {
            String testLine = line.length() == 0 ? word : line + " " + word;
            if (testLine.length() * 5 > maxWidth && line.length() > 0) {
                checkPageSpace(15);
                drawText(line.toString(), x, y);
                y -= 12;
                line = new StringBuilder(word);
            } else {
                line.append(line.length() == 0 ? "" : " ").append(word);
            }
        }

        if (line.length() > 0) {
            checkPageSpace(15);
            drawText(line.toString(), x, y);
            y -= 12;
        }

        return y;
    }

    private float drawTextWithLineBreaks(String text, float x, float y, float maxWidth) throws IOException {
        if (text == null || text.isEmpty()) return y;

        // Split by actual line breaks first
        String[] lines = text.split("\\r?\\n");

        for (String line : lines) {
            if (line.trim().isEmpty()) {
                // Empty line, just add spacing
                y -= 12;
                continue;
            }

            // Now wrap each line if it's too long
            String[] words = line.split(" ");
            StringBuilder currentLine = new StringBuilder();

            for (String word : words) {
                String testLine = currentLine.length() == 0 ? word : currentLine + " " + word;
                if (testLine.length() * 5 > maxWidth && currentLine.length() > 0) {
                    checkPageSpace(15);
                    drawText(currentLine.toString(), x, y);
                    y -= 12;
                    currentLine = new StringBuilder(word);
                } else {
                    currentLine.append(currentLine.length() == 0 ? "" : " ").append(word);
                }
            }

            if (currentLine.length() > 0) {
                checkPageSpace(15);
                drawText(currentLine.toString(), x, y);
                y -= 12;
            }
        }

        return y;
    }

    private Color getSeverityColor(String severity) {
        return switch (severity.toUpperCase()) {
            case "CRITICAL" -> new Color(139, 0, 0);
            case "HIGH" -> new Color(220, 38, 38);
            case "MEDIUM" -> new Color(234, 179, 8);
            case "LOW" -> new Color(59, 130, 246);
            default -> Color.GRAY;
        };
    }

    private Color getColorForSeverity(String severity) {
        return switch (severity.toUpperCase()) {
            case "CRITICAL" -> new Color(139, 0, 0);
            case "HIGH" -> new Color(220, 38, 38);
            case "MEDIUM" -> new Color(255, 165, 0);
            case "LOW" -> new Color(100, 149, 237);
            case "INFO" -> new Color(128, 128, 128);
            default -> Color.GRAY;
        };
    }

    private String extractSpecName(String specLocation) {
        if (specLocation == null) return "Unknown";
        String[] parts = specLocation.split("/");
        return parts[parts.length - 1];
    }

    private String formatDuration(Duration duration) {
        long seconds = duration.getSeconds();
        long minutes = seconds / 60;
        long remainingSeconds = seconds % 60;

        if (minutes > 0) {
            return minutes + "m " + remainingSeconds + "s";
        }
        return seconds + "s";
    }

    @Override
    public ReportFormat getFormat() {
        return ReportFormat.PDF;
    }
}
