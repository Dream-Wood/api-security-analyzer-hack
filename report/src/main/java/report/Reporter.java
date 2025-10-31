package report;

import java.io.IOException;
import java.io.PrintWriter;

/**
 * Interface for generating analysis reports in different formats.
 */
public interface Reporter {

    /**
     * Generate a report from analysis results.
     *
     * @param report the unified analysis report
     * @param writer the output writer
     * @throws IOException if writing fails
     */
    void generate(AnalysisReport report, PrintWriter writer) throws IOException;

    /**
     * Get the format supported by this reporter.
     *
     * @return the report format
     */
    ReportFormat getFormat();
}
